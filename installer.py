#!/usr/bin/env python3
"""
Cross-platform installer for Tor-Search MCP Server.
Uses only Python standard library - no external dependencies.

Requirements: Python 3.11+
"""

import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

# ===========================================================================
# Constants
# ===========================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
COMPONENTS_DIR = SCRIPT_DIR / "components"
CONFIG_FILE = SCRIPT_DIR / "config.toml"
VENV_DIR = SCRIPT_DIR / ".venv"


# ===========================================================================
# Version Fetching
# ===========================================================================


def fetch_latest_geckodriver_version() -> str:
    """Fetch the latest geckodriver version from GitHub releases API."""
    url = "https://api.github.com/repos/mozilla/geckodriver/releases/latest"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "tor-search-mcp-installer",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    ctx = ssl.create_default_context()

    with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))
        return data["tag_name"]  # e.g., "v0.36.0"


def fetch_latest_tor_browser_version() -> tuple[str, dict]:
    """Fetch the latest Tor Browser version and download URLs from Tor Project API."""
    url = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"
    request = urllib.request.Request(url, headers={"User-Agent": "tor-search-mcp-installer"})
    ctx = ssl.create_default_context()

    with urllib.request.urlopen(request, context=ctx, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))

        version = data["version"]
        downloads = data["downloads"]
        base_url = f"https://dist.torproject.org/torbrowser/{version}"

        # Extract URLs from API, with fallback construction for missing platforms
        urls = {
            "darwin": (
                downloads.get("macos", {}).get("ALL", {}).get("binary")
                or f"{base_url}/tor-browser-macos-{version}.dmg"
            ),
            "linux_x86_64": (
                downloads.get("linux-x86_64", {}).get("ALL", {}).get("binary")
                or f"{base_url}/tor-browser-linux-x86_64-{version}.tar.xz"
            ),
            "linux_aarch64": (
                downloads.get("linux-aarch64", {}).get("ALL", {}).get("binary")
                or f"{base_url}/tor-browser-linux-aarch64-{version}.tar.xz"
            ),
            "win32_x86_64": (
                downloads.get("win64", {}).get("ALL", {}).get("binary")
                or f"{base_url}/tor-browser-windows-x86_64-portable-{version}.exe"
            ),
            "win32_aarch64": (
                downloads.get("win64", {}).get("ALL", {}).get("binary")
                or f"{base_url}/tor-browser-windows-x86_64-portable-{version}.exe"
            ),
        }

        return version, urls


def get_geckodriver_url(os_name: str, arch: str) -> tuple[str, str]:
    """
    Get the download URL for geckodriver for the specified platform.

    Returns:
        Tuple of (version, download_url)
    """
    version = fetch_latest_geckodriver_version()

    # Build platform-specific URL
    if os_name == "darwin":
        if arch == "arm64":
            filename = f"geckodriver-{version}-macos-aarch64.tar.gz"
        else:
            filename = f"geckodriver-{version}-macos.tar.gz"
    elif os_name == "linux":
        if arch == "aarch64":
            filename = f"geckodriver-{version}-linux-aarch64.tar.gz"
        else:
            filename = f"geckodriver-{version}-linux64.tar.gz"
    elif os_name == "win32":
        filename = f"geckodriver-{version}-win64.zip"
    else:
        raise RuntimeError(f"Unsupported platform: {os_name}")

    url = f"https://github.com/mozilla/geckodriver/releases/download/{version}/{filename}"
    return version, url


def get_tor_browser_url(os_name: str, arch: str) -> tuple[str, str]:
    """
    Get the download URL for Tor Browser for the specified platform.

    Returns:
        Tuple of (version, download_url)
    """
    version, urls = fetch_latest_tor_browser_version()

    # Get platform-specific URL
    if os_name == "darwin":
        url = urls.get("darwin")
    elif os_name == "linux":
        url_key = f"linux_{arch}"
        url = urls.get(url_key)
    elif os_name == "win32":
        url_key = f"win32_{arch}"
        url = urls.get(url_key)
    else:
        raise RuntimeError(f"Unsupported platform: {os_name}")

    if not url:
        raise RuntimeError(f"No Tor Browser download available for {os_name}/{arch}")

    return version, url


# Common DuckDuckGo regions (code, description)
COMMON_REGIONS = [
    ("us-en", "United States"),
    ("uk-en", "United Kingdom"),
    ("au-en", "Australia"),
    ("ca-en", "Canada"),
    ("de-de", "Germany"),
    ("fr-fr", "France"),
    ("es-es", "Spain"),
    ("it-it", "Italy"),
    ("jp-jp", "Japan"),
    ("br-pt", "Brazil"),
]


# ===========================================================================
# Platform Detection
# ===========================================================================


def detect_platform() -> tuple[str, str]:
    """
    Detect OS and architecture.

    Returns:
        Tuple of (os_name, arch) where:
        - os_name: 'darwin', 'linux', 'win32'
        - arch: 'x86_64', 'arm64', 'aarch64'
    """
    os_name = sys.platform  # 'darwin', 'linux', 'win32'

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64" if os_name == "darwin" else "aarch64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return os_name, arch


# ===========================================================================
# SSL Certificate Helper
# ===========================================================================


def get_venv_cert_path() -> Optional[str]:
    """
    Get the certificate bundle path from the virtual environment's certifi.

    On macOS and Windows, system certificates often cause SSL verification errors.
    This uses the venv's Python to get certifi's certificate bundle path.

    Returns:
        Path to certificate bundle, or None if not available.
    """
    if sys.platform == "win32":
        venv_python = VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python = VENV_DIR / "bin" / "python"

    if not venv_python.exists():
        return None

    try:
        result = subprocess.run(
            [str(venv_python), "-c", "import certifi; print(certifi.where())"],
            capture_output=True,
            text=True,
            check=True,
        )
        cert_path = result.stdout.strip()
        if cert_path and Path(cert_path).exists():
            return cert_path
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


# ===========================================================================
# Idempotency Checks
# ===========================================================================


def check_venv_exists() -> bool:
    """Check if virtual environment exists and is valid."""
    if sys.platform == "win32":
        venv_python = VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python = VENV_DIR / "bin" / "python"
    return venv_python.exists()


def check_requirements_installed(platform_name: str) -> bool:
    """Check if platform requirements are already installed."""
    req_file = SCRIPT_DIR / f"requirements-{platform_name}.txt"
    if not req_file.exists():
        return False

    if sys.platform == "win32":
        venv_pip = VENV_DIR / "Scripts" / "pip.exe"
    else:
        venv_pip = VENV_DIR / "bin" / "pip"

    if not venv_pip.exists():
        return False

    try:
        result = subprocess.run(
            [str(venv_pip), "freeze"],
            capture_output=True,
            text=True,
            check=True,
        )
        installed = set(
            pkg.split("==")[0].lower()
            for pkg in result.stdout.strip().split("\n")
            if pkg
        )

        with open(req_file) as f:
            required = set(
                line.strip().split(">=")[0].split("==")[0].lower()
                for line in f
                if line.strip() and not line.startswith("#")
            )

        return required.issubset(installed)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_geckodriver_exists() -> bool:
    """Check if geckodriver is installed in components folder."""
    if sys.platform == "win32":
        geckodriver_path = COMPONENTS_DIR / "geckodriver.exe"
        return geckodriver_path.exists()
    geckodriver_path = COMPONENTS_DIR / "geckodriver"
    return geckodriver_path.exists() and os.access(geckodriver_path, os.X_OK)


def check_tor_browser_exists() -> bool:
    """Check if Tor Browser is installed."""
    if sys.platform == "darwin":
        return (COMPONENTS_DIR / "Tor Browser.app").exists()
    elif sys.platform == "linux":
        return (COMPONENTS_DIR / "tor-browser").exists()
    else:  # Windows
        return (COMPONENTS_DIR / "TorBrowser" / "Browser" / "firefox.exe").exists()


def check_tor_browser_profile_exists() -> bool:
    """Check if Tor Browser profile directory exists (macOS and Windows)."""
    if sys.platform == "darwin":
        profile_path = COMPONENTS_DIR / "Tor Browser.app" / "Contents" / "Resources" / "TorBrowser" / "Data" / "Browser" / "profile.default"
        return profile_path.is_dir()
    elif sys.platform == "win32":
        profile_path = COMPONENTS_DIR / "TorBrowser" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default"
        return profile_path.is_dir()
    else:  # Linux
        return True  # Linux profile is created automatically


def check_config_exists() -> bool:
    """Check if config.toml exists."""
    return CONFIG_FILE.exists()


# ===========================================================================
# Download Helpers
# ===========================================================================


def download_file(url: str, dest: Path, desc: str) -> None:
    """Download file with progress indication."""
    print(f"    Downloading {desc}...")

    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    # Create SSL context for secure downloads
    ctx = ssl.create_default_context()

    # On macOS and Windows, use certifi certificates from venv if available
    cert_path = get_venv_cert_path()
    if cert_path:
        ctx.load_verify_locations(cafile=cert_path)

    try:
        with urllib.request.urlopen(request, timeout=300, context=ctx) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 65536

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = (downloaded / total_size) * 100
                        mb_downloaded = downloaded / (1024 * 1024)
                        mb_total = total_size / (1024 * 1024)
                        print(
                            f"\r    Progress: {pct:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)",
                            end="",
                            flush=True,
                        )

        print()  # Newline after progress
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to download {url}: {e}")


# ===========================================================================
# Installation Steps
# ===========================================================================


def create_venv() -> None:
    """Create virtual environment in project folder."""
    print("[1/7] Creating virtual environment...")

    if check_venv_exists():
        print("    [SKIP] Virtual environment already exists")
        return

    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    print("    [DONE] Virtual environment created at .venv/")


def install_requirements(platform_name: str) -> None:
    """Install platform-specific requirements into venv."""
    print(f"[2/7] Installing {platform_name} requirements...")

    if check_requirements_installed(platform_name):
        print("    [SKIP] Requirements already installed")
        return

    req_file = SCRIPT_DIR / f"requirements-{platform_name}.txt"
    if sys.platform == "win32":
        venv_pip = VENV_DIR / "Scripts" / "pip.exe"
    else:
        venv_pip = VENV_DIR / "bin" / "pip"

    # Upgrade pip first
    subprocess.run(
        [str(venv_pip), "install", "--upgrade", "pip"],
        check=True,
        capture_output=True,
    )

    # Install requirements
    subprocess.run(
        [str(venv_pip), "install", "-r", str(req_file)],
        check=True,
    )
    print(f"    [DONE] Installed requirements from {req_file.name}")


def setup_geckodriver(os_name: str, arch: str) -> None:
    """Download and setup geckodriver (macOS/Linux)."""
    print("[3/7] Setting up geckodriver...")

    if check_geckodriver_exists():
        print("    [SKIP] geckodriver already installed")
        return

    COMPONENTS_DIR.mkdir(exist_ok=True)

    # Get the latest version and URL dynamically
    version, url = get_geckodriver_url(os_name, arch)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / "geckodriver.tar.gz"
        download_file(url, archive_path, f"geckodriver {version}")

        # Extract
        print("    Extracting...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(COMPONENTS_DIR)

        # Make executable
        geckodriver_path = COMPONENTS_DIR / "geckodriver"
        os.chmod(geckodriver_path, 0o755)

    print("    [DONE] geckodriver installed at components/geckodriver")


def setup_geckodriver_windows(arch: str) -> None:
    """Download and setup geckodriver on Windows (.zip)."""
    print("[3/7] Setting up geckodriver...")

    if check_geckodriver_exists():
        print("    [SKIP] geckodriver already installed")
        return

    COMPONENTS_DIR.mkdir(exist_ok=True)

    # Get the latest version and URL dynamically
    version, url = get_geckodriver_url("win32", arch)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / "geckodriver.zip"
        download_file(url, archive_path, f"geckodriver {version}")

        # Extract ZIP
        print("    Extracting...")
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            zip_ref.extractall(COMPONENTS_DIR)

    print("    [DONE] geckodriver installed at components/geckodriver.exe")


def setup_tor_browser_macos() -> None:
    """Download and setup Tor Browser on macOS (.dmg)."""
    print("[4/7] Setting up Tor Browser...")

    if check_tor_browser_exists():
        print("    [SKIP] Tor Browser already installed")
        return

    COMPONENTS_DIR.mkdir(exist_ok=True)

    # Get the latest version and URL dynamically
    version, url = get_tor_browser_url("darwin", "arm64")  # URL is universal for macOS

    with tempfile.TemporaryDirectory() as tmpdir:
        dmg_path = Path(tmpdir) / "TorBrowser.dmg"
        download_file(url, dmg_path, f"Tor Browser v{version}")

        # Mount DMG
        print("    Mounting DMG...")
        mount_point = Path(tmpdir) / "mount"
        mount_point.mkdir()

        subprocess.run(
            [
                "hdiutil",
                "attach",
                str(dmg_path),
                "-mountpoint",
                str(mount_point),
                "-nobrowse",
                "-quiet",
            ],
            check=True,
        )

        try:
            # Find and copy .app bundle
            print("    Copying Tor Browser.app...")
            src_app = mount_point / "Tor Browser.app"
            dest_app = COMPONENTS_DIR / "Tor Browser.app"

            if src_app.exists():
                shutil.copytree(src_app, dest_app, symlinks=True)
            else:
                raise RuntimeError("Tor Browser.app not found in DMG")
        finally:
            # Unmount DMG
            subprocess.run(
                ["hdiutil", "detach", str(mount_point), "-quiet"],
                capture_output=True,
            )

    print("    [DONE] Tor Browser installed at components/Tor Browser.app")


def ensure_tor_browser_profile_macos() -> None:
    """
    Ensure in-bundle Tor Browser profile directory exists for tbselenium.

    Fresh Tor Browser 15.x installations don't include the profile.default
    directory until first manual launch. tbselenium requires this directory
    to exist, even if empty.
    """
    print("    Ensuring Tor Browser profile exists...")

    profile_path = COMPONENTS_DIR / "Tor Browser.app" / "Contents" / "Resources" / "TorBrowser" / "Data" / "Browser" / "profile.default"

    if profile_path.exists():
        print("    [OK] Profile directory exists")
        return

    profile_path.mkdir(parents=True, exist_ok=True)
    (profile_path / "extensions").mkdir(exist_ok=True)
    print("    [DONE] Created profile directory")


def setup_tor_browser_linux(arch: str) -> None:
    """Download and setup Tor Browser on Linux (tarball)."""
    print("[4/7] Setting up Tor Browser...")

    if check_tor_browser_exists():
        print("    [SKIP] Tor Browser already installed")
        return

    COMPONENTS_DIR.mkdir(exist_ok=True)

    # Get the latest version and URL dynamically
    version, url = get_tor_browser_url("linux", arch)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / "tor-browser.tar.xz"
        download_file(url, archive_path, f"Tor Browser v{version}")

        # Extract (tar.xz) - need to use subprocess since tarfile doesn't handle xz well in older Python
        print("    Extracting...")
        subprocess.run(
            ["tar", "-xJf", str(archive_path), "-C", str(COMPONENTS_DIR)],
            check=True,
        )

    print("    [DONE] Tor Browser installed at components/tor-browser/")


def setup_tor_browser_windows(arch: str) -> None:
    """Download and setup Tor Browser on Windows (portable version)."""
    print("[4/7] Setting up Tor Browser...")

    if check_tor_browser_exists():
        print("    [SKIP] Tor Browser already installed")
        return

    COMPONENTS_DIR.mkdir(exist_ok=True)

    # Get the latest version and URL dynamically
    version, url = get_tor_browser_url("win32", arch)

    # Download to components directory (not temp) to avoid file locking issues
    installer_path = COMPONENTS_DIR / "torbrowser-installer.exe"
    try:
        download_file(url, installer_path, f"Tor Browser v{version}")

        # The portable version is an NSIS installer.
        # Use silent install flags: /S = silent (uppercase!), /D= must be last.
        # The path must be absolute and should NOT have quotes.
        # Use "TorBrowser" (no space) to avoid NSIS path parsing issues.
        dest_dir = (COMPONENTS_DIR / "TorBrowser").resolve()
        print("    Installing Tor Browser silently...")
        subprocess.run(
            [str(installer_path), "/S", f"/D={dest_dir}"],
            check=True,
        )
    finally:
        # Clean up installer after installation completes
        if installer_path.exists():
            try:
                installer_path.unlink()
            except OSError:
                pass  # Ignore cleanup errors

    print("    [DONE] Tor Browser installed at components/TorBrowser/")


def ensure_tor_browser_profile_windows() -> None:
    """
    Ensure Tor Browser profile directory exists on Windows.

    Fresh installations may not include profile.default until first launch.
    tbselenium-windows requires this directory to exist.
    """
    print("    Ensuring Tor Browser profile exists...")

    profile_path = (
        COMPONENTS_DIR / "TorBrowser" / "Browser" / "TorBrowser" /
        "Data" / "Browser" / "profile.default"
    )

    if profile_path.exists():
        print("    [OK] Profile directory exists")
        return

    profile_path.mkdir(parents=True, exist_ok=True)
    (profile_path / "extensions").mkdir(exist_ok=True)
    print("    [DONE] Created profile directory")


def prompt_region() -> str:
    """Prompt user for DuckDuckGo region setting."""
    print("\n[5/7] Configuration")
    print("    DuckDuckGo search region determines result language and localization.")
    print()
    print("    Common regions:")
    for code, description in COMMON_REGIONS:
        print(f"      • {code:<8} ({description})")
    print()

    default = "us-en"
    user_input = input(f"    Press ENTER to use default ({default}), or type a region code: ").strip()

    return user_input if user_input else default


def read_existing_region() -> Optional[str]:
    """Read region from existing config.toml."""
    if not CONFIG_FILE.exists():
        return None

    try:
        with open(CONFIG_FILE) as f:
            for line in f:
                if line.strip().startswith("region"):
                    # Parse: region = "us-en"
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        value = parts[1].strip().strip('"').strip("'")
                        return value
    except Exception:
        pass
    return None


def write_config(os_name: str, region: str) -> None:
    """Write config.toml with settings."""
    print("[6/7] Writing configuration...")

    # Determine paths based on platform - all platforms now use native mode
    if os_name == "darwin":
        tbb_path = str(COMPONENTS_DIR / "Tor Browser.app")
        geckodriver_path = str(COMPONENTS_DIR / "geckodriver")
    elif os_name == "linux":
        tbb_path = str(COMPONENTS_DIR / "tor-browser")
        geckodriver_path = str(COMPONENTS_DIR / "geckodriver")
    else:  # Windows
        # Use forward slashes to avoid TOML escape sequence issues with backslashes
        tbb_path = str(COMPONENTS_DIR / "TorBrowser").replace("\\", "/")
        geckodriver_path = str(COMPONENTS_DIR / "geckodriver.exe").replace("\\", "/")

    config_content = f'''# Tor-Search MCP Server Configuration
# Generated by installer.py

[server]
platform = "{os_name}"
mode = "native"

[search]
region = "{region}"
safesearch = "off"
max_results_per_query = 5

[browser]
tbb_path = "{tbb_path}"
geckodriver_path = "{geckodriver_path}"
page_timeout = 10
overall_timeout = 60
max_concurrent_tabs = 5

[tor]
keepalive_seconds = 120
data_dir = "tor_data"
'''

    with open(CONFIG_FILE, "w") as f:
        f.write(config_content)

    print("    [DONE] Configuration written to config.toml")


def print_mcp_json(os_name: str) -> None:
    """Print mcp.json snippet with absolute paths."""
    print("\n[7/7] MCP Configuration")
    print("=" * 60)

    if os_name == "win32":
        # Use forward slashes for Windows paths in JSON to avoid escape issues
        venv_python = str(VENV_DIR / "Scripts" / "python.exe").replace("\\", "/")
        server_path = str(SCRIPT_DIR / "server.py").replace("\\", "/")
    else:
        venv_python = str(VENV_DIR / "bin" / "python")
        server_path = str(SCRIPT_DIR / "server.py")

    mcp_config: dict = {
        "mcpServers": {
            "tor-search-mcp": {
                "command": venv_python,
                "args": [server_path],
            }
        }
    }

    # Add TBB_PATH env var for all platforms
    if os_name == "darwin":
        tbb_path = str(COMPONENTS_DIR / "Tor Browser.app")
    elif os_name == "linux":
        tbb_path = str(COMPONENTS_DIR / "tor-browser")
    else:  # Windows
        tbb_path = str(COMPONENTS_DIR / "TorBrowser").replace("\\", "/")

    mcp_config["mcpServers"]["tor-search-mcp"]["env"] = {"TBB_PATH": tbb_path}

    print("\nAdd this to your mcp.json in LM Studio, Ollama, or other LLM client:\n")
    print(json.dumps(mcp_config, indent=2))
    print("\n" + "=" * 60)


# ===========================================================================
# Main Entry Point
# ===========================================================================


def main() -> int:
    """Main installer entry point."""
    print("=" * 60)
    print("Tor-Search MCP Server Installer")
    print("=" * 60)

    # Check Python version
    if sys.version_info < (3, 11):
        print(f"\nError: Python 3.11+ is required. You have Python {sys.version_info.major}.{sys.version_info.minor}")
        return 1

    try:
        # Detect platform
        os_name, arch = detect_platform()
        print(f"\nDetected platform: {os_name}/{arch}")

        # Map to requirements file name
        platform_names = {
            "darwin": "macos",
            "linux": "linux",
            "win32": "windows",
        }
        platform_name = platform_names[os_name]

        # Step 1: Create venv
        create_venv()

        # Step 2: Install requirements
        install_requirements(platform_name)

        # Step 3: Setup geckodriver
        if os_name == "win32":
            setup_geckodriver_windows(arch)
        else:
            setup_geckodriver(os_name, arch)

        # Step 4: Setup Tor Browser
        if os_name == "darwin":
            setup_tor_browser_macos()
            ensure_tor_browser_profile_macos()
        elif os_name == "linux":
            setup_tor_browser_linux(arch)
        else:  # Windows
            setup_tor_browser_windows(arch)
            ensure_tor_browser_profile_windows()

        # Step 5: Prompt for region (skip if config exists)
        existing_region = read_existing_region()
        if existing_region:
            print("\n[5/7] Configuration")
            print(f"    [SKIP] config.toml exists with region: {existing_region}")
            region = existing_region
        else:
            region = prompt_region()

        # Step 6: Write config
        write_config(os_name, region)

        # Step 7: Print mcp.json
        print_mcp_json(os_name)

        print("\nInstallation complete!")
        return 0

    except KeyboardInterrupt:
        print("\n\nInstallation cancelled.")
        return 1
    except subprocess.CalledProcessError as e:
        print(f"\n\nError: Command failed: {' '.join(str(x) for x in e.cmd)}")
        if e.stderr:
            print(f"Stderr: {e.stderr}")
        return 1
    except Exception as e:
        print(f"\n\nError: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
