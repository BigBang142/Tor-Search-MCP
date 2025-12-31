#!/usr/bin/env python3
"""
Combined Tor Search + Page Fetch MCP Server.

Provides three tools:
- get_sources: Search DuckDuckGo anonymously through Tor
- fetch_pages: Fetch full page content for search results by index
- fetch_specific_page: Fetch a specific URL directly

Uses a single shared Tor instance for both search and browser fetching.

Supports all platforms (macOS, Linux, Windows) using native tbselenium browser automation:
- macOS: tbselenium-macos
- Linux: tbselenium
- Windows: tbselenium-windows
"""

import configparser
import json
import os
import subprocess
import sys
import threading
import time
import tomllib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Protocol

from fastmcp import FastMCP
from ddgs import DDGS


# ---------------------------------------------------------------------------
# Configuration Loading
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load configuration from config.toml."""
    config_path = Path(__file__).parent / "config.toml"
    if not config_path.exists():
        raise RuntimeError(
            "config.toml not found. Run 'python installer.py' first."
        )
    with open(config_path, "rb") as f:
        return tomllib.load(f)


# Load config at module level
try:
    CONFIG = load_config()
except RuntimeError:
    # Allow import without config for testing purposes
    CONFIG = None

# Initialize MCP server
mcp = FastMCP(name="tor-search-mcp")

# ---------------------------------------------------------------------------
# Configuration Constants (can be overridden by config.toml)
# ---------------------------------------------------------------------------

TOR_KEEPALIVE_SECONDS = CONFIG.get("tor", {}).get("keepalive_seconds", 120) if CONFIG else 120
MAX_CONCURRENT_TABS = CONFIG.get("browser", {}).get("max_concurrent_tabs", 5) if CONFIG else 5
DEFAULT_PAGE_TIMEOUT = CONFIG.get("browser", {}).get("page_timeout", 10) if CONFIG else 10
DEFAULT_OVERALL_TIMEOUT = CONFIG.get("browser", {}).get("overall_timeout", 60) if CONFIG else 60
DEFAULT_TOR_DATA_DIR = os.path.join(os.path.dirname(__file__), CONFIG.get("tor", {}).get("data_dir", "tor_data") if CONFIG else "tor_data")
SEARCH_REGION = CONFIG.get("search", {}).get("region", "us-en") if CONFIG else "us-en"
SEARCH_SAFESEARCH = CONFIG.get("search", {}).get("safesearch", "off") if CONFIG else "off"


# ---------------------------------------------------------------------------
# Browser Backend Protocol
# ---------------------------------------------------------------------------

class BrowserBackend(Protocol):
    """Protocol for browser automation backends."""

    def start_tor(self) -> None:
        """Start Tor connection."""
        ...

    def stop_tor(self) -> None:
        """Stop Tor connection."""
        ...

    def get_socks_port(self) -> int:
        """Get SOCKS proxy port for DDGS."""
        ...

    def is_tor_running(self) -> bool:
        """Check if Tor is currently running."""
        ...

    def check_tor_timeout(self) -> bool:
        """Check if Tor has timed out. Returns True if still valid."""
        ...

    def fetch_urls(self, urls: list[str], page_timeout: int, overall_timeout: int) -> dict:
        """Fetch multiple URLs and return content."""
        ...

# ---------------------------------------------------------------------------
# Global State
# ---------------------------------------------------------------------------

_tor_process = None
_tor_socks_port: Optional[int] = None
_tor_control_port: Optional[int] = None
_tor_start_time: Optional[float] = None
_tbb_path: Optional[str] = None
_tbb_profile_path: Optional[str] = None
_last_search_results: list = []
_fetch_pages_called: bool = False
_state_lock = threading.Lock()


# ---------------------------------------------------------------------------
# tbselenium Lazy Import Helpers (Platform-Aware)
# ---------------------------------------------------------------------------


def _is_macos() -> bool:
    """Check if the current platform is macOS."""
    return sys.platform == "darwin"


def _is_windows() -> bool:
    """Check if the current platform is Windows."""
    return sys.platform == "win32"


def _is_linux() -> bool:
    """Check if the current platform is Linux."""
    return sys.platform.startswith("linux")


def _needs_virtual_display() -> bool:
    """Check if a virtual display is needed (Linux without DISPLAY)."""
    if not _is_linux():
        return False
    # Check if DISPLAY environment variable is set
    return not os.environ.get("DISPLAY")


def _find_tor_browser_linux() -> Optional[str]:
    """
    Find Tor Browser installation on Linux.

    Searches common installation locations and verifies the path
    contains Browser/firefox to confirm it's a valid Tor Browser.

    Returns:
        Path to Tor Browser directory, or None if not found.
    """
    # Common Linux Tor Browser locations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths = [
        os.path.join(script_dir, "components", "tor-browser"),  # Installer location
        os.path.expanduser("~/tor-browser"),
        os.path.expanduser("~/.tor-browser"),
        "/opt/tor-browser",
        "/usr/local/tor-browser",
    ]

    for path in search_paths:
        if not os.path.isdir(path):
            continue
        # Verify it's a valid Tor Browser by checking for Browser/firefox
        firefox_path = os.path.join(path, "Browser", "firefox")
        if os.path.exists(firefox_path):
            return path

    return None


def _ensure_tbselenium():
    """Import the appropriate tbselenium package for the current platform."""
    if _is_macos():
        import tbselenium_macos  # noqa: F401
    elif _is_windows():
        import tbselenium_windows  # noqa: F401
    else:
        import tbselenium  # noqa: F401


def _get_tbselenium_common():
    """Get the tbselenium common module for the current platform."""
    _ensure_tbselenium()
    if _is_macos():
        import tbselenium_macos.common as cm
    elif _is_windows():
        import tbselenium_windows.common as cm
    else:
        import tbselenium.common as cm
    return cm


def _resolve_tbb_path(explicit_path: Optional[str] = None) -> Optional[str]:
    """Resolve Tor Browser path from CLI, env, or common locations."""
    if explicit_path:
        candidate = explicit_path
    else:
        candidate = os.environ.get("TBB_PATH") or os.environ.get("TOR_BROWSER_PATH")

    if not candidate:
        # Use platform-specific finder functions
        if _is_macos():
            _ensure_tbselenium()
            from tbselenium_macos.utils import find_tor_browser_app
            candidate = find_tor_browser_app()
        elif _is_windows():
            _ensure_tbselenium()
            from tbselenium_windows.utils import find_tor_browser_dir
            candidate = find_tor_browser_dir()
        else:
            # Linux: use our custom finder (tbselenium.utils doesn't have find_tor_browser_app)
            candidate = _find_tor_browser_linux()

    if not candidate:
        return None

    candidate = os.path.abspath(os.path.expanduser(candidate))
    if not os.path.isdir(candidate):
        return None

    return candidate


def _resolve_profile_path(tbb_path: str, explicit_profile_path: Optional[str] = None) -> Optional[str]:
    """Resolve a Tor Browser profile directory."""
    if explicit_profile_path:
        candidate = os.path.abspath(os.path.expanduser(explicit_profile_path))
        return candidate if os.path.isdir(candidate) else None

    cm = _get_tbselenium_common()

    # First try the in-bundle profile path expected by tbselenium
    bundle_profile = os.path.join(tbb_path, cm.DEFAULT_TBB_PROFILE_PATH)
    if os.path.isdir(bundle_profile):
        return bundle_profile

    # Platform-specific profile fallbacks
    if _is_macos():
        # macOS: user profile in Application Support
        support_base = os.path.expanduser("~/Library/Application Support/TorBrowser-Data/Browser")
    elif _is_windows():
        # Windows: Tor Browser stores profile in the bundle only, no external location
        return None
    else:
        # Linux: user profile in home directory
        support_base = os.path.expanduser("~/.tor-browser/Browser/TorBrowser/Data/Browser")
        if not os.path.isdir(support_base):
            # Alternative Linux location
            support_base = os.path.expanduser("~/tor-browser/Browser/TorBrowser/Data/Browser")

    if not os.path.isdir(support_base):
        return None

    profiles_ini = os.path.join(support_base, "profiles.ini")
    if os.path.isfile(profiles_ini):
        parser = configparser.ConfigParser()
        parser.read(profiles_ini)
        for section in parser.sections():
            if not section.startswith("Profile"):
                continue
            if parser.get(section, "Default", fallback="0") == "1":
                path_value = parser.get(section, "Path", fallback="")
                is_relative = parser.get(section, "IsRelative", fallback="1") == "1"
                if path_value:
                    candidate = os.path.join(support_base, path_value) if is_relative else path_value
                    candidate = os.path.abspath(os.path.expanduser(candidate))
                    if os.path.isdir(candidate):
                        return candidate

    # Final fallback: first directory ending with .default
    try:
        for name in os.listdir(support_base):
            if name.endswith(".default"):
                candidate = os.path.join(support_base, name)
                if os.path.isdir(candidate):
                    return candidate
    except OSError:
        return None

    return None


# ---------------------------------------------------------------------------
# Tor Lifecycle Management
# ---------------------------------------------------------------------------


def _start_tor() -> tuple:
    """
    Start Tor using tbselenium's launch_tbb_tor_with_stem.

    Returns:
        tuple: (tor_process, socks_port, control_port, tbb_path, profile_path)

    Raises:
        RuntimeError: If Tor Browser not found or Tor fails to start.
    """
    global _tor_process, _tor_socks_port, _tor_control_port, _tor_start_time
    global _tbb_path, _tbb_profile_path

    _ensure_tbselenium()
    if _is_macos():
        from tbselenium_macos import launch_tbb_tor_with_stem
    elif _is_windows():
        from tbselenium_windows import launch_tbb_tor_with_stem
    else:
        from tbselenium.utils import launch_tbb_tor_with_stem
    cm = _get_tbselenium_common()

    # Resolve paths
    tbb_path = _resolve_tbb_path()
    if not tbb_path:
        raise RuntimeError(
            "Tor Browser not found. Set TBB_PATH environment variable or install Tor Browser."
        )

    profile_path = _resolve_profile_path(tbb_path)
    if not profile_path:
        raise RuntimeError(
            "Tor Browser profile not found. Open Tor Browser once to create a profile."
        )

    # Ensure tor_data directory exists
    os.makedirs(DEFAULT_TOR_DATA_DIR, exist_ok=True)

    # Configure Tor
    torrc_config = {
        "DataDirectory": os.path.abspath(DEFAULT_TOR_DATA_DIR),
        "SOCKSPort": str(cm.STEM_SOCKS_PORT),
        "ControlPort": str(cm.STEM_CONTROL_PORT),
    }

    tor_process = launch_tbb_tor_with_stem(tbb_path=tbb_path, torrc=torrc_config)

    # Store state
    _tor_process = tor_process
    _tor_socks_port = cm.STEM_SOCKS_PORT
    _tor_control_port = cm.STEM_CONTROL_PORT
    _tor_start_time = time.time()
    _tbb_path = tbb_path
    _tbb_profile_path = profile_path

    return tor_process, cm.STEM_SOCKS_PORT, cm.STEM_CONTROL_PORT, tbb_path, profile_path


def _kill_tor():
    """Terminate the running Tor process if any."""
    global _tor_process, _tor_socks_port, _tor_control_port, _tor_start_time

    if _tor_process:
        try:
            _tor_process.kill()
        except Exception:
            pass
        finally:
            _tor_process = None
            _tor_socks_port = None
            _tor_control_port = None
            _tor_start_time = None


def _check_tor_timeout() -> bool:
    """
    Check if Tor has timed out (exceeded keepalive period).

    Returns:
        bool: True if Tor is still valid, False if timed out or not running.
    """
    global _tor_start_time

    if _tor_process is None or _tor_start_time is None:
        return False

    elapsed = time.time() - _tor_start_time
    if elapsed > TOR_KEEPALIVE_SECONDS:
        _kill_tor()
        return False

    return True


# ---------------------------------------------------------------------------
# Trafilatura Content Extraction
# ---------------------------------------------------------------------------


def _extract_with_trafilatura(html: str, url: Optional[str] = None) -> Optional[str]:
    """
    Extract clean content from HTML using Trafilatura.

    Returns JSON string with extracted content or None if extraction fails.
    """
    import trafilatura

    try:
        extracted = trafilatura.extract(
            html,
            url=url,
            include_formatting=True,
            include_tables=True,
            include_links=True,
            include_comments=False,
            favor_precision=True,
            deduplicate=True,
            output_format="json",
        )
        return extracted
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Browser Fetch Helpers (adapted from host_manager.py)
# ---------------------------------------------------------------------------


def _dispatch_batch(driver, urls: list) -> tuple:
    """
    Open tabs and trigger navigation for a batch of URLs.

    Returns:
        tuple: (tab_url_map, tab_dispatch_times)
    """
    tab_url_map = {}
    tab_dispatch_times = {}

    for i, url in enumerate(urls):
        if i == 0:
            handle = driver.current_window_handle
        else:
            driver.execute_script("window.open('');")
            handle = driver.window_handles[-1]
            driver.switch_to.window(handle)

        tab_url_map[handle] = url

        try:
            tab_dispatch_times[url] = time.time()
            driver.get(url)
        except Exception:
            pass

    return tab_url_map, tab_dispatch_times


def _collect_batch(driver, tab_url_map: dict, tab_dispatch_times: dict, timeout: int, deadline: Optional[float] = None) -> tuple:
    """
    Poll tabs until ready and collect results.

    Returns:
        tuple: (results, tab_load_times)
    """
    results = {}
    tab_load_times = {}
    pending = set(tab_url_map.keys())
    start = time.time()

    def _deadline_exceeded():
        return deadline is not None and time.time() > deadline

    while pending and (time.time() - start) < timeout and not _deadline_exceeded():
        for handle in list(pending):
            try:
                driver.switch_to.window(handle)
            except Exception as e:
                url = tab_url_map[handle]
                results[url] = {"error": "tab_error", "message": str(e)}
                if url in tab_dispatch_times:
                    tab_load_times[url] = round(time.time() - tab_dispatch_times[url], 3)
                pending.remove(handle)
                continue

            url = tab_url_map[handle]

            try:
                ready_state = driver.execute_script("return document.readyState;")
            except Exception as e:
                results[url] = {"error": "script_error", "message": str(e)}
                if url in tab_dispatch_times:
                    tab_load_times[url] = round(time.time() - tab_dispatch_times[url], 3)
                pending.remove(handle)
                continue

            if ready_state in ("complete", "interactive"):
                if url in tab_dispatch_times:
                    load_time = round(time.time() - tab_dispatch_times[url], 3)
                    tab_load_times[url] = load_time

                try:
                    if hasattr(driver, "is_connection_error_page") and driver.is_connection_error_page:
                        results[url] = {
                            "error": "connection_error",
                            "message": f"Site unreachable: {url}",
                        }
                    else:
                        html = driver.page_source
                        if html:
                            results[url] = html
                        else:
                            results[url] = {"error": "empty_response", "message": "No HTML content"}
                except Exception as e:
                    results[url] = {"error": "capture_error", "message": str(e)}

                try:
                    if len(driver.window_handles) > 1:
                        driver.close()
                except Exception:
                    pass

                pending.remove(handle)

        if pending and not _deadline_exceeded():
            time.sleep(0.5)

    # Handle remaining tabs that timed out
    for handle in list(pending):
        try:
            driver.switch_to.window(handle)
            url = tab_url_map[handle]
            if url in tab_dispatch_times:
                tab_load_times[url] = round(time.time() - tab_dispatch_times[url], 3)

            try:
                html = driver.page_source
                if html and len(html.strip()) > 0:
                    results[url] = html
                else:
                    results[url] = {"error": "timeout", "message": "Page load timed out"}
            except Exception:
                results[url] = {"error": "timeout", "message": "Page load timed out"}

            try:
                if len(driver.window_handles) > 1:
                    driver.close()
            except Exception:
                pass
        except Exception as e:
            url = tab_url_map.get(handle, "unknown")
            results[url] = {"error": "timeout", "message": f"Tab error: {e}"}
            if url in tab_dispatch_times:
                tab_load_times[url] = round(time.time() - tab_dispatch_times[url], 3)

    return results, tab_load_times


def _fetch_urls_with_browser(urls: list, page_timeout: int = DEFAULT_PAGE_TIMEOUT, overall_timeout: int = DEFAULT_OVERALL_TIMEOUT) -> dict:
    """
    Fetch multiple URLs using Tor Browser connected to the existing Tor process.

    Returns:
        dict: {url: extracted_content_or_error_dict}
    """
    global _tbb_path, _tbb_profile_path

    _ensure_tbselenium()
    if _is_macos():
        from tbselenium_macos import TorBrowserDriver, USE_STEM
    elif _is_windows():
        from tbselenium_windows import TorBrowserDriver, USE_STEM
    else:
        from tbselenium.tbdriver import TorBrowserDriver
        from tbselenium.common import USE_STEM
    from selenium.webdriver.firefox.options import Options

    if not _tbb_path or not _tbb_profile_path:
        raise RuntimeError("Tor Browser paths not initialized. Call _start_tor() first.")

    driver = None
    virtual_display = None
    results = {}
    total_start = time.time()

    # Use platform-appropriate null device for log suppression
    tbb_logfile_path = "NUL" if _is_windows() else "/dev/null"

    try:
        # Start virtual display on Linux if no DISPLAY is available
        if _needs_virtual_display():
            try:
                from pyvirtualdisplay import Display
                virtual_display = Display(visible=False, size=(1920, 1080))
                virtual_display.start()
            except ImportError:
                raise RuntimeError(
                    "pyvirtualdisplay is required for headless execution on Linux. "
                    "Install with: pip install pyvirtualdisplay && sudo apt-get install xvfb"
                )

        options = Options()
        options.page_load_strategy = "eager"

        driver = TorBrowserDriver(
            tbb_path=_tbb_path,
            tor_cfg=USE_STEM,
            tbb_logfile_path=tbb_logfile_path,
            tor_data_dir=os.path.abspath(DEFAULT_TOR_DATA_DIR),
            headless=True,
            options=options,
            tbb_profile_path=_tbb_profile_path,
        )

        driver.set_page_load_timeout(page_timeout)

        deadline = None
        if overall_timeout and overall_timeout > 0:
            deadline = total_start + overall_timeout

        # Process URLs in batches
        all_results = {}
        for i in range(0, len(urls), MAX_CONCURRENT_TABS):
            if deadline is not None and time.time() > deadline:
                remaining = urls[i:]
                for url in remaining:
                    all_results[url] = {"error": "timeout", "message": "Overall timeout reached"}
                break

            batch = urls[i:i + MAX_CONCURRENT_TABS]

            tab_url_map, tab_dispatch_times = _dispatch_batch(driver, batch)
            batch_results, _ = _collect_batch(driver, tab_url_map, tab_dispatch_times, page_timeout, deadline=deadline)
            all_results.update(batch_results)

        # Extract content with Trafilatura
        for url, content in all_results.items():
            if isinstance(content, str):
                extracted = _extract_with_trafilatura(content, url=url)
                if extracted:
                    results[url] = extracted
                else:
                    results[url] = {
                        "error": "extraction_error",
                        "message": "Trafilatura failed to extract content",
                    }
            else:
                results[url] = content

    except Exception as e:
        for url in urls:
            if url not in results:
                results[url] = {"error": "browser_error", "message": str(e)}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        if virtual_display:
            try:
                virtual_display.stop()
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Native Browser Backend (all platforms)
# ---------------------------------------------------------------------------


class NativeBrowserBackend:
    """Native browser backend using tbselenium for macOS/Linux/Windows."""

    def __init__(self):
        self._tor_process = None
        self._tor_socks_port: Optional[int] = None
        self._tor_control_port: Optional[int] = None
        self._tor_start_time: Optional[float] = None
        self._tbb_path: Optional[str] = None
        self._tbb_profile_path: Optional[str] = None
        self._lock = threading.Lock()

    def start_tor(self) -> None:
        """Start Tor using tbselenium's launch_tbb_tor_with_stem."""
        with self._lock:
            # Use the module-level _start_tor function
            result = _start_tor()
            # Update our internal state
            self._tor_process = _tor_process
            self._tor_socks_port = _tor_socks_port
            self._tor_control_port = _tor_control_port
            self._tor_start_time = _tor_start_time
            self._tbb_path = _tbb_path
            self._tbb_profile_path = _tbb_profile_path

    def stop_tor(self) -> None:
        """Stop Tor process."""
        with self._lock:
            _kill_tor()
            self._tor_process = None
            self._tor_socks_port = None
            self._tor_control_port = None
            self._tor_start_time = None

    def get_socks_port(self) -> int:
        """Get SOCKS proxy port."""
        return self._tor_socks_port or _tor_socks_port or 9150

    def is_tor_running(self) -> bool:
        """Check if Tor is running."""
        return _tor_process is not None

    def check_tor_timeout(self) -> bool:
        """Check if Tor has timed out. Returns True if still valid."""
        return _check_tor_timeout()

    def fetch_urls(self, urls: list[str], page_timeout: int, overall_timeout: int) -> dict:
        """Fetch URLs using native browser."""
        return _fetch_urls_with_browser(urls, page_timeout, overall_timeout)


# ---------------------------------------------------------------------------
# Backend Factory
# ---------------------------------------------------------------------------


def _create_backend() -> BrowserBackend:
    """Factory function to create the browser backend."""
    return NativeBrowserBackend()


# Global backend instance
BACKEND: BrowserBackend = _create_backend()


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def get_sources(queries: list[str]) -> str:
    """
    Search DuckDuckGo anonymously through Tor. Accepts 1-3 search queries, returning up to 5 results
    per query (max 15 total). Results are indexed linearly across all queries and deduplicated by URL.

    WHEN TO USE MULTIPLE QUERIES:
    - Use multiple queries when the topic is ambiguous or could be phrased different ways
    - Use multiple queries when different phrasings might yield complementary results
    - Use multiple queries when the question spans multiple distinct concepts
    - Stick with a single well-crafted query when the information need is straightforward and specific

    The goal is appropriate query count, not always maximizing to three. A focused single query often
    outperforms multiple vague ones.

    IMPORTANT: After calling this tool, you MUST call fetch_pages to retrieve the full content
    of the relevant results. This is required to provide comprehensive answers to user questions.
    The search results only contain snippets - the full page content is needed for accurate responses.
    """
    global _last_search_results, _fetch_pages_called

    # Validate queries
    if not queries or len(queries) == 0:
        raise ValueError("At least one query is required.")
    if len(queries) > 3:
        raise ValueError("Maximum of 3 queries allowed.")

    with _state_lock:
        # Kill any existing Tor (handles re-search scenario)
        if BACKEND.is_tor_running():
            BACKEND.stop_tor()

        try:
            # Start Tor
            BACKEND.start_tor()

            # Configure DDGS to use Tor SOCKS proxy
            ddgs = DDGS(proxy=f"socks5h://127.0.0.1:{BACKEND.get_socks_port()}", timeout=60)

            # Track seen URLs for deduplication
            seen_urls = set()
            _last_search_results = []
            current_index = 1

            # Results grouped by query for formatted output
            results_by_query = []

            # Perform searches sequentially
            for query in queries:
                results = list(ddgs.text(query, region=SEARCH_REGION, safesearch=SEARCH_SAFESEARCH, max_results=5))

                query_results = []
                for r in results:
                    url = r.get("href", "")

                    # Skip duplicates
                    if url in seen_urls:
                        continue

                    seen_urls.add(url)

                    # Truncate snippet to 125 characters
                    snippet = r.get("body", "")
                    if len(snippet) > 125:
                        snippet = snippet[:125] + "..."

                    item = {
                        "index": current_index,
                        "title": r.get("title", ""),
                        "url": url,
                        "snippet": snippet,
                    }
                    _last_search_results.append(item)
                    query_results.append(item)
                    current_index += 1

                results_by_query.append({
                    "query": query,
                    "results": query_results,
                })

            # Reset fetch flag
            _fetch_pages_called = False

            # Format results as Markdown with H2 headers per query
            output_parts = []
            for group in results_by_query:
                query = group["query"]
                query_results = group["results"]

                output_parts.append(f"## Query: \"{query}\"")

                if not query_results:
                    output_parts.append("_No unique results for this query._\n")
                else:
                    entries = []
                    for item in query_results:
                        idx = item["index"]
                        title = item["title"]
                        url = item["url"]
                        snippet = item["snippet"]
                        blockquote = "\n".join(f"> {line}" for line in snippet.split("\n"))
                        entries.append(f"### {idx}. [{title}]({url})\n{blockquote}")
                    output_parts.append("\n\n".join(entries))

                output_parts.append("")  # Add spacing between query sections

            return "\n".join(output_parts)

        except Exception:
            BACKEND.stop_tor()
            raise


@mcp.tool()
def fetch_pages(indexes: list[int]) -> str:
    """
    Fetch the full page content for search results by their index numbers.

    This tool MUST be called after get_sources. You can only call this once per search.
    Pass indexes like [1, 3, 11] for the results you want to fetch.

    IMPORTANT: With multi-query searches, up to 15 results may be available (5 per query, minus
    duplicates), but you can only fetch a maximum of 5 pages per call. Choose the most relevant
    indexes based on the abbreviated snippets and source credibility shown in get_sources results.
    Review all query sections before selecting - relevant results may appear under any query.

    ERROR conditions:
    - If called without a preceding get_sources call
    - If called more than once per search
    - If Tor connection has timed out (>2 minutes since get_sources)
    - If more than 5 indexes are requested
    """
    global _fetch_pages_called

    with _state_lock:
        # Validate state
        if not _last_search_results:
            raise RuntimeError(
                "No search results available. You must call get_sources first before fetch_pages."
            )

        if _fetch_pages_called:
            raise RuntimeError(
                "fetch_pages has already been called for this search. "
                "Call get_sources again to perform a new search."
            )

        if not BACKEND.check_tor_timeout():
            raise RuntimeError(
                "Tor connection has timed out. Call get_sources again to start a new search."
            )

        # Validate number of indexes
        if len(indexes) > 5:
            raise ValueError(
                f"Maximum of 5 pages can be fetched per call. You requested {len(indexes)}. "
                "Choose the most relevant indexes based on snippets and source credibility."
            )

        # Validate indexes
        valid_indexes = {item["index"] for item in _last_search_results}
        for idx in indexes:
            if idx not in valid_indexes:
                raise ValueError(
                    f"Invalid index {idx}. Valid indexes are: {sorted(valid_indexes)}"
                )

        # Extract URLs
        urls_to_fetch = []
        for item in _last_search_results:
            if item["index"] in indexes:
                urls_to_fetch.append(item["url"])

        if not urls_to_fetch:
            raise ValueError("No valid URLs to fetch based on provided indexes.")

        # Mark as fetched
        _fetch_pages_called = True

        try:
            # Fetch pages using backend
            results = BACKEND.fetch_urls(urls_to_fetch, DEFAULT_PAGE_TIMEOUT, DEFAULT_OVERALL_TIMEOUT)

            # Format results
            output_parts = []
            for item in _last_search_results:
                if item["index"] in indexes:
                    url = item["url"]
                    title = item["title"]
                    content = results.get(url)

                    output_parts.append(f"## {item['index']}. {title}")
                    output_parts.append(f"URL: {url}\n")

                    if isinstance(content, str):
                        # Parse JSON from Trafilatura
                        try:
                            data = json.loads(content)
                            text = data.get("text", content)
                            output_parts.append(text)
                        except json.JSONDecodeError:
                            output_parts.append(content)
                    elif isinstance(content, dict):
                        error_type = content.get("error", "unknown")
                        error_msg = content.get("message", "Unknown error")
                        output_parts.append(f"**Error fetching page:** [{error_type}] {error_msg}")
                    else:
                        output_parts.append("**Error:** No content retrieved")

                    output_parts.append("\n---\n")

            return "\n".join(output_parts)

        finally:
            # Always kill Tor after fetch_pages
            BACKEND.stop_tor()


@mcp.tool()
def fetch_specific_page(url: str) -> str:
    """
    Fetch a specific page by URL. Use this pretty much only when the user provides a direct URL in their prompt.

    For general web research, ALWAYS use the get_sources -> fetch_pages workflow instead. NEVER use this tool to fetch links fro get_sources. This tool is meant for cases where a URL is provided to you by the user or another tool.

    The tool will start a fresh Tor connection, fetch and return the page, and terminate the connection.
    """
    with _state_lock:
        # Kill any existing Tor (clean state)
        if BACKEND.is_tor_running():
            BACKEND.stop_tor()

        try:
            # Start Tor
            BACKEND.start_tor()

            # Fetch the page
            results = BACKEND.fetch_urls([url], DEFAULT_PAGE_TIMEOUT, DEFAULT_OVERALL_TIMEOUT)

            content = results.get(url)

            if isinstance(content, str):
                # Parse JSON from Trafilatura
                try:
                    data = json.loads(content)
                    text = data.get("text", content)
                    return f"## Content from {url}\n\n{text}"
                except json.JSONDecodeError:
                    return f"## Content from {url}\n\n{content}"
            elif isinstance(content, dict):
                error_type = content.get("error", "unknown")
                error_msg = content.get("message", "Unknown error")
                raise RuntimeError(f"Failed to fetch page: [{error_type}] {error_msg}")
            else:
                raise RuntimeError("No content retrieved from page")

        finally:
            # Always kill Tor after fetch
            BACKEND.stop_tor()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
