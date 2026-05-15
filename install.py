#!/usr/bin/env python3
# install.py — Gauntlet Hardware Security Assessment Web Platform
# VERSION: referenced from /opt/pr0t31n/Gauntlet/VERSION
# Installs all dependencies for app.py and configures the system service.

import argparse
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"

def cprint(msg: str, colour: str = RESET, bold: bool = False) -> None:
    prefix = BOLD if bold else ""
    print(f"{prefix}{colour}{msg}{RESET}")

def phase_header(title: str) -> None:
    bar = "=" * 60
    print()
    cprint(bar, CYAN, bold=True)
    cprint(f"  {title}", CYAN, bold=True)
    cprint(bar, CYAN, bold=True)

def info(msg: str)    -> None: cprint(f"  [*] {msg}", BLUE)
def success(msg: str) -> None: cprint(f"  [+] {msg}", GREEN)
def warn(msg: str)    -> None: cprint(f"  [!] {msg}", YELLOW)
def error(msg: str)   -> None: cprint(f"  [-] {msg}", RED)

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return one of: macos | kali | ubuntu | rhel | suse | windows | unknown"""
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        release_files = ["/etc/os-release", "/usr/lib/os-release"]
        release_info = {}
        for rf in release_files:
            if os.path.exists(rf):
                with open(rf) as fh:
                    for line in fh:
                        line = line.strip()
                        if "=" in line:
                            k, _, v = line.partition("=")
                            release_info[k] = v.strip('"').lower()
                break
        name = release_info.get("ID", "")
        like = release_info.get("ID_LIKE", "")
        if "kali" in name:
            return "kali"
        if "ubuntu" in name or "ubuntu" in like:
            return "ubuntu"
        if name in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in like or "fedora" in like:
            return "rhel"
        if name in ("opensuse", "sles", "suse") or "suse" in like:
            return "suse"
        if "debian" in name or "debian" in like:
            return "ubuntu"
    return "unknown"

# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------

def run(cmd: list, check: bool = False, dry_run: bool = False,
        env: dict = None, cwd: str = None) -> int:
    """Run a command; return exit code. If dry_run, just print and return 0."""
    display = " ".join(str(c) for c in cmd)
    if dry_run:
        cprint(f"    [DRY-RUN] {display}", MAGENTA)
        return 0
    info(f"Running: {display}")
    try:
        result = subprocess.run(
            cmd,
            env={**os.environ, **(env or {})},
            cwd=cwd,
        )
        if check and result.returncode != 0:
            error(f"Command failed (exit {result.returncode}): {display}")
        return result.returncode
    except FileNotFoundError:
        error(f"Executable not found for command: {display}")
        return 127
    except Exception as exc:
        error(f"Unexpected error running {display}: {exc}")
        return 1

# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0

def require_root() -> None:
    if not is_root():
        error("This installer must be run as root (or with sudo) on Linux.")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Package lists
# ---------------------------------------------------------------------------

APT_PACKAGES = [
    "python3-pip", "python3-dev", "git", "openssl", "libssl-dev",
]

DNF_PACKAGES = [
    "python3-pip", "python3-devel", "git", "openssl", "openssl-devel",
]

ZYPPER_PACKAGES = [
    "python3-pip", "python3-devel", "git", "openssl", "libopenssl-devel",
]

BREW_PACKAGES = ["openssl", "git"]

PIP_PACKAGES = [
    "flask>=3.0.0",
    "flask-socketio>=5.3.6",
    "pyyaml>=6.0.1",
    "eventlet>=0.35.0",
    "psutil>=5.9.0",
    "dpkt>=1.9.8",
    "netifaces>=0.11.0",
]

# ---------------------------------------------------------------------------
# Phase 1 — System packages
# ---------------------------------------------------------------------------

def phase_apt(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (apt)")
    require_root()
    info("Updating package lists…")
    run(["apt-get", "update", "-y"], check=True, dry_run=dry_run)
    info("Upgrading installed packages…")
    run(["apt-get", "upgrade", "-y"], check=True, dry_run=dry_run)
    info(f"Installing: {' '.join(APT_PACKAGES)}")
    run(["apt-get", "install", "-y"] + APT_PACKAGES, check=True, dry_run=dry_run)


def phase_dnf(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (dnf)")
    require_root()
    run(["dnf", "upgrade", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(DNF_PACKAGES)}")
    run(["dnf", "install", "-y"] + DNF_PACKAGES, check=True, dry_run=dry_run)


def phase_zypper(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (zypper)")
    require_root()
    run(["zypper", "refresh"], dry_run=dry_run)
    run(["zypper", "update", "-y"], dry_run=dry_run)
    info(f"Installing: {' '.join(ZYPPER_PACKAGES)}")
    run(["zypper", "install", "-y"] + ZYPPER_PACKAGES, check=True, dry_run=dry_run)


def phase_brew(dry_run: bool) -> None:
    phase_header("PHASE 1 — System Packages (Homebrew / macOS)")

    brew_bin = shutil.which("brew")
    if not brew_bin:
        error("Homebrew not found. Install from https://brew.sh and re-run.")
        return

    if is_root():
        sudo_user = os.environ.get("SUDO_USER", "")
        if not sudo_user:
            warn("Running as root but SUDO_USER is not set — skipping brew install "
                 "to avoid corrupting Homebrew. Re-run as your normal user.")
            return
        base_cmd = ["sudo", "-u", sudo_user, brew_bin]
    else:
        base_cmd = [brew_bin]

    info(f"Installing brew packages: {' '.join(BREW_PACKAGES)}")
    run(base_cmd + ["install"] + BREW_PACKAGES, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Phase 2 — Pip
# ---------------------------------------------------------------------------

def find_pip() -> str:
    """Return the best available pip executable."""
    for candidate in ("pip3", "pip", "python3 -m pip"):
        if " " in candidate:
            # python3 -m pip — check python3 exists
            if shutil.which("python3"):
                return candidate
        elif shutil.which(candidate):
            return candidate
    return "pip3"


def phase_pip(dry_run: bool) -> None:
    phase_header("PHASE 2 — Python Packages (pip)")

    pip_exe = find_pip()
    if " " in pip_exe:
        base_cmd = pip_exe.split()
    else:
        base_cmd = [pip_exe]

    for pkg in PIP_PACKAGES:
        info(f"Installing pip package: {pkg}")
        run(base_cmd + ["install", "--break-system-packages", pkg],
            check=True, dry_run=dry_run)

    success("Pip phase complete.")


# ---------------------------------------------------------------------------
# Phase 3 — Go (none for Gauntlet)
# ---------------------------------------------------------------------------

def phase_go(dry_run: bool) -> None:
    phase_header("PHASE 3 — Go Tools")
    info("Gauntlet does not use any Go tools — skipping.")
    success("Go phase complete (nothing to install).")


# ---------------------------------------------------------------------------
# Phase 4 — Git (none for Gauntlet)
# ---------------------------------------------------------------------------

def phase_git(dry_run: bool) -> None:
    phase_header("PHASE 4 — Git Repositories")
    info("Gauntlet has no external git repositories to clone.")
    info("NOTE: Gearbox must be installed separately — see install.py in the Gearbox directory.")
    success("Git phase complete (nothing to install).")


# ---------------------------------------------------------------------------
# Phase 5 — Static assets
# ---------------------------------------------------------------------------

SOCKET_IO_URL      = "https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"
SOCKET_IO_DEST     = Path("/opt/pr0t31n/Gauntlet/static/js/socket.io.min.js")
SOCKET_IO_MIN_BYTES = 40_000


def phase_static_assets(dry_run: bool) -> None:
    phase_header("PHASE 5 — Static Assets")
    SOCKET_IO_DEST.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_IO_DEST.exists() and SOCKET_IO_DEST.stat().st_size >= SOCKET_IO_MIN_BYTES:
        success(f"socket.io.min.js already present ({SOCKET_IO_DEST.stat().st_size} bytes) — skipping.")
        return
    info("Downloading socket.io.min.js from CDN…")
    if dry_run:
        cprint(f"    [DRY-RUN] Would download {SOCKET_IO_URL} → {SOCKET_IO_DEST}", MAGENTA)
        return
    try:
        import urllib.request
        urllib.request.urlretrieve(SOCKET_IO_URL, SOCKET_IO_DEST)
        success(f"Downloaded socket.io.min.js ({SOCKET_IO_DEST.stat().st_size} bytes)")
    except Exception as exc:
        warn(f"CDN download failed: {exc}")
        warn("socket.io.min.js is also vendored in the git repo — re-run 'git pull' to restore it.")


# ---------------------------------------------------------------------------
# Phase 6 — Service installation (Flask app — no symlinks)
# ---------------------------------------------------------------------------

SYSTEMD_UNIT = """\
[Unit]
Description=Gauntlet Hardware Security Assessment Web Platform
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/pr0t31n/Gauntlet/app.py
WorkingDirectory=/opt/pr0t31n/Gauntlet
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pr0t31n.gauntlet</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/opt/pr0t31n/Gauntlet/app.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/pr0t31n/Gauntlet</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/gauntlet.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/gauntlet.err</string>
</dict>
</plist>
"""


def phase_service(os_id: str, dry_run: bool) -> None:
    phase_header("PHASE 6 — Service Installation")
    info("Gauntlet is a Flask app — no /usr/local/bin symlink created.")

    if os_id in ("kali", "ubuntu", "rhel", "suse"):
        service_path = Path("/etc/systemd/system/pr0t31n-gauntlet.service")
        info(f"Writing systemd unit: {service_path}")
        if not dry_run:
            try:
                service_path.write_text(SYSTEMD_UNIT)
                run(["systemctl", "daemon-reload"], dry_run=dry_run)
                run(["systemctl", "enable", "pr0t31n-gauntlet"], dry_run=dry_run)
                success(f"Systemd service installed: {service_path}")
                info("Start with:  systemctl start pr0t31n-gauntlet")
                info("Gauntlet will be available on port 5700.")
            except OSError as exc:
                error(f"Failed to write service file: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {service_path}", MAGENTA)
            cprint(f"    [DRY-RUN] systemctl daemon-reload && systemctl enable pr0t31n-gauntlet", MAGENTA)

    elif os_id == "macos":
        plist_path = Path("/Library/LaunchDaemons/com.pr0t31n.gauntlet.plist")
        info(f"Writing launchd plist: {plist_path}")
        if not dry_run:
            try:
                plist_path.write_text(LAUNCHD_PLIST)
                run(["launchctl", "load", str(plist_path)], dry_run=dry_run)
                success(f"Launchd plist installed: {plist_path}")
                info("Gauntlet will start automatically on boot and is available on port 5700.")
            except OSError as exc:
                error(f"Failed to write plist: {exc}")
        else:
            cprint(f"    [DRY-RUN] Would write {plist_path}", MAGENTA)

    elif os_id == "windows":
        warn("Windows detected. To run Gauntlet manually:")
        warn("  cd C:\\opt\\pr0t31n\\Gauntlet && python app.py")
        warn("For background service, consider using NSSM: https://nssm.cc/")
    else:
        warn(f"Unknown OS '{os_id}' — service installation skipped.")


# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

VERIFY_PY_MODULES = [
    ("flask",        "flask"),
    ("flask_socketio","flask_socketio"),
    ("yaml",         "yaml"),
    ("eventlet",     "eventlet"),
    ("psutil",       "psutil"),
    ("dpkt",         "dpkt"),
    ("netifaces",    "netifaces"),
]


def phase_verify(os_id: str) -> None:
    phase_header("POST-INSTALL SUMMARY")
    all_ok = True

    cprint("  Python modules:", BOLD)
    for display_name, import_name in VERIFY_PY_MODULES:
        spec = importlib.util.find_spec(import_name)
        if spec is not None:
            success(f"  {display_name:20s} importable")
        else:
            warn(f"  {display_name:20s} NOT FOUND — run: pip install --break-system-packages {display_name}")
            all_ok = False

    print()
    cprint("  App paths:", BOLD)
    app_path = Path("/opt/pr0t31n/Gauntlet/app.py")
    if app_path.exists():
        success(f"  {str(app_path):40s} exists")
    else:
        warn(f"  {str(app_path):40s} NOT FOUND — check your Gauntlet installation")
        all_ok = False

    if SOCKET_IO_DEST.exists() and SOCKET_IO_DEST.stat().st_size >= SOCKET_IO_MIN_BYTES:
        success(f"  {str(SOCKET_IO_DEST):40s} present")
    else:
        warn(f"  {str(SOCKET_IO_DEST):40s} MISSING — run install.py again")
        all_ok = False

    if os_id in ("kali", "ubuntu", "rhel", "suse"):
        svc = Path("/etc/systemd/system/pr0t31n-gauntlet.service")
        if svc.exists():
            success(f"  {str(svc):40s} installed")
        else:
            warn(f"  {str(svc):40s} not installed")
    elif os_id == "macos":
        plist = Path("/Library/LaunchDaemons/com.pr0t31n.gauntlet.plist")
        if plist.exists():
            success(f"  {str(plist):40s} installed")
        else:
            warn(f"  {str(plist):40s} not installed")

    print()
    if all_ok:
        success("All dependencies verified successfully.")
    else:
        warn("Some dependencies are missing. Review warnings above.")

    info("Note: Gearbox must be installed separately before launching Gauntlet.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Gauntlet installer — Hardware Security Assessment Web Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--skip-apt",  action="store_true", help="Skip system package installation")
    p.add_argument("--skip-pip",  action="store_true", help="Skip pip package installation")
    p.add_argument("--skip-go",   action="store_true", help="Skip Go tool installation (no-op for Gauntlet)")
    p.add_argument("--skip-git",  action="store_true", help="Skip git repository cloning (no-op for Gauntlet)")
    p.add_argument("--check",     action="store_true", help="Dry-run — print commands without executing")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    dry_run = args.check

    cprint("\n" + "=" * 60, GREEN, bold=True)
    cprint("  Gauntlet Installer", GREEN, bold=True)
    cprint("  Hardware Security Assessment Web Platform", GREEN, bold=True)
    cprint("=" * 60 + "\n", GREEN, bold=True)

    if dry_run:
        warn("DRY-RUN MODE — no changes will be made to this system.\n")

    os_id = detect_os()
    info(f"Detected OS: {os_id}")

    if os_id == "windows":
        warn("Windows detected.")
        warn("Gauntlet is a Flask application and can be run manually:")
        warn("  cd C:\\opt\\pr0t31n\\Gauntlet")
        warn("  pip install flask flask-socketio pyyaml eventlet psutil dpkt netifaces")
        warn("  python app.py")
        sys.exit(0)

    # Phase 1 — system packages
    if not args.skip_apt:
        if os_id in ("kali", "ubuntu"):
            phase_apt(dry_run)
        elif os_id == "rhel":
            phase_dnf(dry_run)
        elif os_id == "suse":
            phase_zypper(dry_run)
        elif os_id == "macos":
            phase_brew(dry_run)
        else:
            warn(f"Unknown OS '{os_id}' — skipping system package phase.")
    else:
        info("Skipping system package phase (--skip-apt).")

    # Phase 2 — pip
    if not args.skip_pip:
        phase_pip(dry_run)
    else:
        info("Skipping pip phase (--skip-pip).")

    # Phase 3 — Go (no-op)
    if not args.skip_go:
        phase_go(dry_run)
    else:
        info("Skipping Go phase (--skip-go).")

    # Phase 4 — Git (no-op)
    if not args.skip_git:
        phase_git(dry_run)
    else:
        info("Skipping git phase (--skip-git).")

    # Phase 5 — Static assets
    phase_static_assets(dry_run)

    # Phase 6 — Service (Flask app — no symlinks)
    if is_root() or dry_run:
        phase_service(os_id, dry_run)
    else:
        warn("Not running as root — skipping service installation. Re-run with sudo to install service.")

    # Verify
    phase_verify(os_id)

    print()
    cprint("  Gauntlet installation complete.", GREEN, bold=True)
    cprint("  Access the web interface at: http://localhost:5700\n", CYAN)


if __name__ == "__main__":
    main()
