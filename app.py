"""
Gauntlet — Flask Application
Manages device security assessment projects and interactive testing via gearbox.py
"""

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, session, Response, after_this_request  # Flask — Armin Ronacher @mitsuhiko (https://github.com/pallets/flask)
from werkzeug.utils import secure_filename  # Werkzeug — Armin Ronacher (https://github.com/pallets/werkzeug)
from flask_socketio import SocketIO, emit, join_room, leave_room  # Flask-SocketIO — Miguel Grinberg @miguelgrinberg (https://github.com/miguelgrinberg/flask-socketio)
import subprocess   # stdlib — launches gearbox.py as a managed subprocess
import threading    # stdlib — per-project reader threads for gearbox stdout/stderr
import queue        # stdlib — answer queues for gearbox interactive prompts
import json         # stdlib — project metadata and findings JSONL serialisation
import yaml         # PyYAML — Kirill Simonov (https://pyyaml.org) — project YAML parsing
import os           # stdlib — path and environment helpers
import re           # stdlib — __GB_ protocol token parsing
import shutil       # stdlib — ZIP export and file operations
import socket       # stdlib — network interface enumeration for QR URLs
import uuid         # stdlib — finding and session unique identifiers
from datetime import datetime, timedelta  # stdlib — timestamp generation / session lifetime
from pathlib import Path        # stdlib — cross-platform path handling
import importlib.util as _imputil  # stdlib — optional module presence checks
import _auth                        # pr0t31n — authentication, TLS and security hardening

# ─── App Setup ─────────────────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(_BASE_DIR, 'templates'),
    static_folder=os.path.join(_BASE_DIR, 'static'),
)
app.config['SECRET_KEY'] = _auth.load_secret_key()
app.config['SESSION_COOKIE_NAME'] = 'gauntlet_session'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 * 1024   # 4 GB upload limit (project zip imports)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0            # disable static file caching
app.config['SESSION_COOKIE_SECURE']      = False  # self-signed cert; HTTPS enforced server-side
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
_auth.init_auth()

@app.context_processor
def _inject_version():
    return {"app_version": VERSION}

@app.after_request
def _no_cache(response):
    # Prevent browsers caching HTML — JS/CSS still cacheable via Flask static
    if 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma']         = 'no-cache'
        response.headers['Expires']        = '0'
    return _auth.apply_security_headers(response)


@app.before_request
def _auth_gate():
    return _auth.auth_gate()
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*', manage_session=False)

import platform as _platform

def _clients_base() -> Path:
    """Return the OS-appropriate clients root directory."""
    system = _platform.system()
    if system == "Darwin":
        base = Path("/Users/Shared/clients")
    elif system == "Windows":
        base = Path("C:/clients")
    else:
        base = Path("/clients")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        base = Path.home() / "clients"
        base.mkdir(parents=True, exist_ok=True)
    return base


def _build_project_dir_structured(client_short: str, start_date: str) -> Path:
    """
    Build a structured Gearbox project directory:
      <clients_base>/<client_short>/<year>/gearbox/<client_short>_<datetime>/
    """
    slug = re.sub(r'[^\w-]', '_', (client_short or 'project').strip().lower()).strip('_') or 'project'
    year = (start_date[:4] if start_date and len(start_date) >= 4 and start_date[:4].isdigit()
            else datetime.now().strftime('%Y'))
    dt_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = _clients_base() / slug / year / "gearbox" / f"{slug}_{dt_str}"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        path = Path.home() / "clients" / "gearbox" / f"{slug}_{dt_str}"
        path.mkdir(parents=True, exist_ok=True)
    return path


def _discover_gearbox_projects() -> list:
    """Walk clients_base for project_meta.json files with tool=gearbox.

    Each entry includes 'project_dir' — the absolute path of the directory
    containing project_meta.json.  This is the authoritative locator for
    discovered projects because not every Gearbox run produces a top-level
    YAML (CLI-driven runs may omit it).  Per-project API routes resolve
    the directory via _project_dir_for(), which prefers project_dir over
    yaml_path so discovered projects without a YAML still load console
    history, findings, and targets.
    """
    base = _clients_base()
    raw = load_projects()
    # Dedup against both keys — a project may have been imported via either.
    existing_yaml = {p.get("yaml_path", "") for p in raw.get("projects", {}).values()
                     if p.get("yaml_path")}
    existing_dirs = {p.get("project_dir", "") for p in raw.get("projects", {}).values()
                     if p.get("project_dir")}
    found = []
    if not base.exists():
        return found
    for meta_file in base.glob("*/*/*/*/project_meta.json"):
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if meta.get("tool") != "gearbox":
                continue
            proj_path = meta_file.parent
            proj_path_str = str(proj_path)
            yaml_files = list(proj_path.glob("*.yaml")) + list(proj_path.glob("*.yml"))
            yaml_path = str(yaml_files[0]) if yaml_files else ""
            if (yaml_path and yaml_path in existing_yaml) or proj_path_str in existing_dirs:
                continue
            found.append({"path": proj_path_str, "project_dir": proj_path_str,
                          "yaml_path": yaml_path, "meta": meta})
        except Exception:
            pass
    return found

# Active gearbox subprocesses keyed by socket session ID
_active_procs: dict[str, subprocess.Popen] = {}
# Answer queues keyed by socket session ID
_answer_queues: dict[str, queue.Queue] = {}
# Instance context set by Evidence tab when directing mobile to capture a photo
_photo_context: dict[str, dict] = {}

# Per-project ring buffers (max 2000 entries each)
_MAX_BUFFER     = 2000
_console_buffer: dict[str, list] = {}   # project_id -> [{text, stream, ts}]
_gearbox_log:    dict[str, list] = {}   # project_id -> [{ts, level, message}]
_gauntlet_log:   dict[str, list] = {}   # project_id -> [{ts, event, sid, ip, ua, data}]
_observations:   dict[str, list] = {}   # project_id -> [{ts, title, desc, tool, version, file, output}]
_error_buffer:   dict[str, list] = {}   # project_id -> [{ts, type, source, message, detail}]

# Log filename for each in-memory buffer
_LOG_FILES = {
    id(_gearbox_log):  'gearbox_log.jsonl',
    id(_gauntlet_log): 'gauntlet_log.jsonl',
    id(_observations): 'observations.jsonl',
    id(_error_buffer): 'errors.jsonl',
}

_project_dir_cache: dict[str, str] = {}  # project_id -> dir path (TTL-free cache)

# Job queue — execute-project requests that arrive while a scan is running
_job_queue: list = []
_queue_lock = threading.Lock()
_QUEUE_FILE = os.path.join(_BASE_DIR, "execute_queue.json")

def _project_dir_for(project_id: str) -> str | None:
    """Return the project output directory path, cached to avoid repeated disk reads.

    Resolution order:
      1. The explicit 'project_dir' field in gauntlet_meta.json (set for projects
         discovered via _discover_gearbox_projects() — works even when no
         YAML file exists in the directory).
      2. dirname(yaml_path) — legacy path for projects created through
         Gauntlet's new_project flow, which always writes a YAML.

    Returns None only when neither field resolves to an existing directory.
    """
    if project_id in _project_dir_cache:
        return _project_dir_cache[project_id]
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return None
    # 1. Prefer explicit project_dir (discovered projects).
    pdir = pinfo.get('project_dir', '')
    if pdir:
        if not os.path.isabs(pdir):
            pdir = os.path.join(_BASE_DIR, pdir)
        if os.path.isdir(pdir):
            _project_dir_cache[project_id] = pdir
            return pdir
    # 2. Fall back to deriving from yaml_path.
    yaml_path = pinfo.get('yaml_path', '')
    if not yaml_path:
        return None
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    d = os.path.dirname(os.path.abspath(yaml_path))
    if os.path.isdir(d):
        _project_dir_cache[project_id] = d
        return d
    return None

def _buf_append(buf: dict, project_id: str, entry: dict) -> None:
    """Append to a ring buffer (trimmed to _MAX_BUFFER) and persist to disk."""
    lst = buf.setdefault(project_id, [])
    lst.append(entry)
    if len(lst) > _MAX_BUFFER:
        del lst[0]
    # Persist to the project directory so logs survive server restarts
    fname = _LOG_FILES.get(id(buf))
    if fname:
        try:
            pdir = _project_dir_for(project_id)
            if pdir:
                log_path = os.path.join(pdir, fname)
                with open(log_path, 'a', encoding='utf-8') as _f:
                    _f.write(json.dumps(entry) + '\n')
        except Exception:
            pass  # log persistence is best-effort


def _load_log_from_disk(project_id: str, filename: str,
                        limit: int = _MAX_BUFFER) -> list:
    """Read the last `limit` log entries from disk for an existing project."""
    pdir = _project_dir_for(project_id)
    if not pdir:
        return []
    log_path = os.path.join(pdir, filename)
    if not os.path.exists(log_path):
        return []
    entries = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        # Return only the last `limit` entries
        return entries[-limit:]
    except Exception:
        return []

def _ts() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ─── Interface & Module Registry (mirrors gearbox.py) ──────────────────────────

INTERFACE_MODULES: dict[str, list[str]] = {
    "Ethernet":     ["Photo", "EthernetIface", "Ethtool", "EthtoolConnectedPhoto",
                     "ConfigDiscovery", "TrafficCollector", "DhcpServer", "NmapLive", "Nessus",
                     "Responder", "NmapPort", "BannerGrab", "Web", "Nuclei", "SSL", "SSH",
                     "FTP", "SMB", "NFS", "EthernetCleanup"],
    "USB":          ["Photo", "UsbPower", "UsbPowerConnectedPhoto", "Keyboard",
                     "KeyboardConnectedPhoto", "KeyCombos", "Mouse", "MouseConnectedPhoto",
                     "BashBunny", "BashBunnyConnectedPhoto"],
    "Ethernet_tap": ["Photo", "Tcpdump_running", "Tcpdump_runningConnectedPhoto",
                     "Tcpdump_boot", "Tcpdump_bootConnectedPhoto", "Tcpdump_shutdown"],
    "HDMI":         ["Photo", "PortType", "Input", "InputConnectedPhoto", "Output",
                     "OutputConnectedPhoto", "EDID", "HdmiDDC", "HdmiHDCP",
                     "HdmiCEC", "HdmiCECConnectedPhoto"],
    "Dvi":          ["Photo", "PortType", "Input", "InputConnectedPhoto", "Output",
                     "OutputConnectedPhoto", "EDID", "HdmiDDC"],
    "sdi":          ["Photo", "PortType", "Input", "InputConnectedPhoto", "Output",
                     "OutputConnectedPhoto", "EDID", "HdmiDDC", "HdmiHDCP",
                     "HdmiCEC", "HdmiCECConnectedPhoto"],
    "Dp":           ["Photo", "PortType", "Input", "InputConnectedPhoto", "Output",
                     "OutputConnectedPhoto", "EDID", "HdmiDDC", "HdmiHDCP",
                     "HdmiCEC", "HdmiCECConnectedPhoto"],
    "Rca":          ["Photo", "Input", "InputConnectedPhoto", "Output", "OutputConnectedPhoto"],
    "Aux":          ["Photo", "Input", "InputConnectedPhoto", "Output", "OutputConnectedPhoto"],
    "Zigbee":       ["Photo", "Sniff", "SniffConnectedPhoto", "Flood"],
    "Bluetooth":    ["Photo", "Bluetooth", "BluetoothConnectedPhoto"],
    "DB9":          ["Photo", "SerialDetect", "SerialDetectConnectedPhoto",
                     "CanAssess", "CanAssessConnectedPhoto"],
    "WiFi":       ["Photo", "WiFi", "WiFiConnectedPhoto"],
    "SubGHz":     ["Photo", "SubGHz", "SubGHzConnectedPhoto"],
    "UWB":        ["Photo", "UWB", "UWBConnectedPhoto"],
    "SmartCard":  ["Photo", "SmartCard", "SmartCardConnectedPhoto"],
    "ZWave":      ["Photo", "ZWave", "ZWaveConnectedPhoto"],
    "LoRa":       ["Photo", "LoRa", "LoRaConnectedPhoto"],
    "RFID":         ["Photo", "RFIDSniff", "RFIDSniffConnectedPhoto", "RFIDReplay"],
}

INTERFACE_TYPES = list(INTERFACE_MODULES.keys())

# Tools used by each module (shown in Evidence tab Tools column)
MODULE_TOOLS: dict[str, list[str]] = {
    "Photo":            ["gowitness"],
    "Ethtool":          ["ethtool"],
    "ConfigDiscovery":  ["tcpdump"],
    "TrafficCollector": ["tcpdump", "tshark"],
    "NmapLive":         ["nmap"],
    "Nessus":           ["nessus"],
    "Responder":        ["responder"],
    "NmapPort":         ["nmap"],
    "BannerGrab":       ["socket", "curl"],
    "Web":              ["curl", "gowitness", "wget", "openssl"],
    "Nuclei":           ["nuclei"],
    "SSL":              ["sslscan", "testssl.sh", "shcheck"],
    "SSH":              ["nmap", "ssh-audit"],
    "SMB":              ["nmap", "smbmap", "responder"],
    "NFS":              ["nmap"],
    "FTP":              ["nmap"],
    "UsbPower":         ["usbmon"],
    "Keyboard":         ["hid-tools"],
    "KeyCombos":        ["hid-tools"],
    "Mouse":            ["hid-tools"],
    "BashBunny":        ["bash-bunny"],
    "Tcpdump_running":  ["tcpdump"],
    "Tcpdump_boot":     ["tcpdump"],
    "Tcpdump_shutdown": ["tcpdump"],
    "PortType":         ["v4l2-ctl", "udevadm"],
    "Input":            ["ffmpeg", "v4l2"],
    "Output":           ["ffmpeg", "v4l2"],
    "EDID":             ["get-edid", "read-edid", "edid-decode"],
    "HdmiDDC":          ["ddcutil", "ddccontrol"],
    "HdmiHDCP":         ["hdcp-check", "v4l2-ctl"],
    "HdmiCEC":          ["cec-client"],
    "Sniff":            ["wireshark", "scapy", "whsniff", "zbdump", "zbstumbler"],
    "Flood":            ["scapy"],
    "Bluetooth":        ["bluetoothctl", "btmgmt", "btmon", "gatttool", "sdptool",
                         "l2ping", "bettercap", "crackle", "sniff_receiver.py",
                         "ubertooth-btle"],
    "SerialDetect":     ["sigrok", "minicom"],
    "CanAssess":        ["can_detect", "candump", "canplayer"],
    "RFIDSniff":        ["proxmark3", "chameleon_cli"],
    "WiFi":            ["airmon-ng", "airodump-ng", "aircrack-ng", "reaver", "bully", "wash", "hcxdumptool", "hcxpcapngtool", "wifite", "bettercap", "mdk4", "iw"],
    "SubGHz":          ["rfcat", "rtl_433", "hackrf_transfer", "hackrf_sweep", "urh_cli"],
    "UWB":             ["uwb-sniffer"],
    "SmartCard":       ["pcsc_scan", "opensc-tool", "gp"],
    "ZWave":           ["ezwave", "rtl_433"],
    "LoRa":            ["rtl_433", "urh_cli"],
    "RFIDReplay":       ["proxmark3", "chameleon_cli"],
}

RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
CLASSIFICATIONS = ["Unconfirmed", "Confirmed", "Validated"]

RISK_COLORS = {
    "Critical":      "#FF00FF",
    "High":          "#E7716F",
    "Medium":        "#FFC000",
    "Low":           "#92D050",
    "Informational": "#BDD7EC",
    "Unknown":       "#a0aec0",
}

# ─── Helpers ───────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """
    Return the machine's primary LAN IP (not loopback).

    Strategy:
    1. Enumerate all network interfaces via netifaces/psutil if available —
       picks the first private-range IPv4 address that isn't loopback.
    2. UDP connect trick (no packets sent) to a well-known address —
       works even without internet access because no route is required.
    3. Enumerate /proc/net/if_inet6 on Linux (last resort).
    4. Fall back to gethostbyname.

    Private ranges checked: 10.x, 172.16-31.x, 192.168.x
    """
    def _is_private(ip: str) -> bool:
        """True for RFC-1918 addresses (not loopback, not link-local)."""
        return (
            ip.startswith('10.') or
            ip.startswith('192.168.') or
            any(ip.startswith(f'172.{n}.') for n in range(16, 32))
        )

    # 1. Try netifaces — most reliable, works offline
    try:
        import netifaces as _ni
        for iface in _ni.interfaces():
            addrs = _ni.ifaddresses(iface).get(_ni.AF_INET, [])
            for addr in addrs:
                ip = addr.get('addr', '')
                if ip and _is_private(ip):
                    return ip
    except ImportError:
        pass
    except Exception:
        pass

    # 2. UDP connect trick — works in isolated networks, no packets sent
    for target in ('10.255.255.255', '192.168.255.255', '172.31.255.255',
                   '8.8.8.8'):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect((target, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                return ip
        except Exception:
            pass

    # 3. Parse /proc/net/fib_trie (Linux — lists all local addresses)
    try:
        with open('/proc/net/fib_trie') as f:
            content = f.read()
        import re as _re
        for ip in _re.findall(r'32 host LOCAL\n.*?(\d+\.\d+\.\d+\.\d+)', content):
            if _is_private(ip):
                return ip
    except Exception:
        pass

    # 4. hostname resolution fallback
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass

    return '127.0.0.1'


def get_all_interfaces() -> list:
    """
    Return a list of dicts: [{name, ip}] for every non-loopback IPv4 interface.
    Tries netifaces first, falls back to socket/ip-addr parsing.
    Excludes loopback (127.x), link-local (169.254.x), and docker bridges by default.
    """
    def _is_usable(ip: str) -> bool:
        return (
            not ip.startswith('127.')
            and not ip.startswith('169.254.')
        )

    results = []

    # 1. netifaces — most complete
    try:
        import netifaces as _ni
        for iface in _ni.interfaces():
            addrs = _ni.ifaddresses(iface).get(_ni.AF_INET, [])
            for addr in addrs:
                ip = addr.get('addr', '')
                if ip and _is_usable(ip):
                    results.append({'name': iface, 'ip': ip})
        if results:
            return results
    except Exception:
        pass

    # 2. Parse `ip -4 addr show` on Linux
    try:
        import subprocess as _sp, re as _re
        out = _sp.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=4)
        iface_name = ''
        for line in out.splitlines():
            m_iface = _re.match(r'^\d+:\s+(\S+):', line)
            if m_iface:
                iface_name = m_iface.group(1).rstrip(':')
            m_addr = _re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if m_addr and iface_name:
                ip = m_addr.group(1)
                if _is_usable(ip):
                    results.append({'name': iface_name, 'ip': ip})
        if results:
            return results
    except Exception:
        pass

    # 3. socket fallback — at least returns one entry
    try:
        ip = get_local_ip()
        if ip and _is_usable(ip):
            results.append({'name': 'eth0', 'ip': ip})
    except Exception:
        pass

    return results or [{'name': 'lo', 'ip': '127.0.0.1'}]


_gauntlet_projects_cache: dict | None = None


def _project_dir_from_entry(entry: dict) -> str:
    pd = entry.get("project_dir", "")
    if pd:
        if not os.path.isabs(pd):
            pd = os.path.join(_BASE_DIR, pd)
        return pd
    yp = entry.get("yaml_path", "")
    if yp:
        if not os.path.isabs(yp):
            yp = os.path.join(_BASE_DIR, yp)
        return os.path.dirname(os.path.abspath(yp))
    return ""


def _scan_gauntlet_meta() -> dict:
    base = _clients_base()
    projects = {}
    if not base.exists():
        return {"projects": projects}
    for meta_file in base.rglob("gauntlet_meta.json"):
        try:
            with open(meta_file, "r") as f:
                meta = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        pid = meta.pop("id", None)
        if not pid:
            continue
        projects[pid] = meta
    return {"projects": projects}


def _migrate_legacy_projects_json() -> None:
    old_file = os.path.join(_BASE_DIR, "projects.json")
    if not os.path.exists(old_file):
        return
    try:
        with open(old_file, "r") as f:
            old_data = json.load(f)
        for pid, entry in old_data.get("projects", {}).items():
            pd = _project_dir_from_entry(entry)
            if pd and os.path.isdir(pd):
                meta_file = os.path.join(pd, "gauntlet_meta.json")
                if not os.path.exists(meta_file):
                    with open(meta_file, "w") as f:
                        json.dump({"id": pid, **entry}, f, indent=2)
        os.rename(old_file, old_file + ".bak")
    except Exception:
        pass


def load_projects() -> dict:
    global _gauntlet_projects_cache
    if _gauntlet_projects_cache is not None:
        return _gauntlet_projects_cache
    _migrate_legacy_projects_json()
    _gauntlet_projects_cache = _scan_gauntlet_meta()
    return _gauntlet_projects_cache


def save_projects(data: dict) -> None:
    global _gauntlet_projects_cache
    new_projects = data.get("projects", {})
    old_projects = (_gauntlet_projects_cache or {}).get("projects", {})
    for pid, entry in new_projects.items():
        pd = _project_dir_from_entry(entry)
        if pd and os.path.isdir(pd):
            meta_file = os.path.join(pd, "gauntlet_meta.json")
            with open(meta_file, "w") as f:
                json.dump({"id": pid, **entry}, f, indent=2)
    for pid in old_projects:
        if pid not in new_projects:
            pd = _project_dir_from_entry(old_projects[pid])
            if pd:
                meta_file = os.path.join(pd, "gauntlet_meta.json")
                try:
                    os.unlink(meta_file)
                except OSError:
                    pass
    _gauntlet_projects_cache = data


def load_yaml(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def migrate_yaml_instance_keys(yaml_path: str) -> tuple[dict, list[str]]:
    """
    Inspect a project YAML for auto-generated keys (subdevice_N, instance_N, inst_N).
    For each found, derive a user-friendly key from the 'name' or 'location' field.
    Rewrites the YAML file in-place if changes are made.

    Also renames any matching directories on disk to match the new keys.

    Returns (updated_yaml_data, list_of_changes_made).
    """
    try:
        data = load_yaml(yaml_path)
    except Exception:
        return {}, []

    changes: list[str] = []
    project_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))
    short  = (data.get('client_short') or 'proj').replace(' ', '_').upper()
    device = (data.get('device') or 'device').replace(' ', '_').replace('/', '-')

    AUTO_SD   = re.compile(r'^subdevice_\d+$')
    AUTO_INST = re.compile(r'^(instance|inst)_\d+$')

    new_subdevices: dict = {}
    for sd_key, sd in list((data.get('subdevices') or {}).items()):
        if not isinstance(sd, dict):
            new_subdevices[sd_key] = sd
            continue

        # Derive a better subdevice key if the current one looks auto-generated
        if AUTO_SD.match(sd_key):
            sd_name   = (sd.get('name') or sd_key).strip()
            new_sd_key = re.sub(r'[^\w]', '_', sd_name).lower() or sd_key
            if new_sd_key != sd_key:
                changes.append(f'Subdevice key: {sd_key!r} → {new_sd_key!r}')
                # Rename directory on disk if it exists
                sd_name_clean = sd_name.replace(' ', '_').replace('/', '-')
                old_sd_dir = project_dir / short / device / sd_name_clean
                # (sd dir is named after sd_name, not sd_key — no dir rename needed here)
        else:
            new_sd_key = sd_key

        sd_name_clean = (sd.get('name') or new_sd_key).replace(' ', '_').replace('/', '-')

        new_interfaces: dict = {}
        for iface, inst_dict in list((sd.get('interfaces') or {}).items()):
            if not isinstance(inst_dict, dict):
                new_interfaces[iface] = inst_dict
                continue

            new_inst_dict: dict = {}
            for inst_key, inst_data in list(inst_dict.items()):
                if not isinstance(inst_data, dict):
                    inst_data = {}

                if AUTO_INST.match(inst_key):
                    loc      = (inst_data.get('location') or inst_data.get('name') or '').strip()
                    new_key  = re.sub(r'[^\w]', '_', loc).lower() if loc else inst_key
                    # Ensure uniqueness within this interface
                    if new_key in new_inst_dict:
                        new_key = f"{new_key}_{inst_key}"
                    if new_key != inst_key:
                        changes.append(
                            f'Instance key: {sd_name_clean}/{iface}/{inst_key!r} → {new_key!r}')
                        # Rename directory on disk
                        old_dir = project_dir / short / device / sd_name_clean / iface / inst_key
                        new_dir = project_dir / short / device / sd_name_clean / iface / new_key
                        if old_dir.exists() and not new_dir.exists():
                            try:
                                old_dir.rename(new_dir)
                                changes[-1] += f' (directory renamed)'
                            except Exception as e:
                                changes[-1] += f' (dir rename failed: {e})'
                        # Also handle paths without sd_name
                        old_dir2 = project_dir / short / device / iface / inst_key
                        new_dir2 = project_dir / short / device / iface / new_key
                        if old_dir2.exists() and not new_dir2.exists():
                            try:
                                old_dir2.rename(new_dir2)
                                changes[-1] += f' (flat directory renamed)'
                            except Exception as e:
                                changes[-1] += f' (flat dir rename failed: {e})'
                else:
                    new_key = inst_key

                new_inst_dict[new_key] = inst_data

            new_interfaces[iface] = new_inst_dict

        sd_copy = dict(sd)
        sd_copy['interfaces'] = new_interfaces
        new_subdevices[new_sd_key] = sd_copy

    if not changes:
        return data, []

    data['subdevices'] = new_subdevices

    # Write updated YAML back to disk
    try:
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False,
                      allow_unicode=True, sort_keys=False)
    except Exception as e:
        changes.append(f'Warning: could not write updated YAML: {e}')

    return data, changes




def status_path(yaml_path: str) -> str:
    base = os.path.splitext(yaml_path)[0]
    return base + '_status.json'


def load_status(yaml_path: str) -> dict:
    sp = status_path(yaml_path)
    if os.path.exists(sp):
        with open(sp, 'r') as f:
            return json.load(f)
    return {}


def load_progress(yaml_path: str) -> dict:
    """Load gearbox progress JSON file from the project directory."""
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    project_dir   = os.path.dirname(os.path.abspath(yaml_path))
    progress_file = os.path.join(project_dir, 'progress.json')
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    # Legacy fallback: yaml-stem prefix
    stem = os.path.splitext(yaml_path)[0]
    legacy = stem + '_progress.json'
    if os.path.exists(legacy):
        try:
            with open(legacy, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def collect_instances(yaml_data: dict) -> list[dict]:
    """
    Build a flat list of all instance descriptors from YAML, mirroring
    gearbox.py's ProjectOrchestrator._collect_instances() exactly.
    Supports list-based subdevices, component-key subdevices, and
    name-keyed interface instances.
    """
    instances = []
    short  = (yaml_data.get('client_short') or 'proj').strip().replace(' ', '_').upper()
    device = (yaml_data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')

    known_ifaces = set(INTERFACE_MODULES.keys())
    _STRUCTURAL  = {"name", "id", "description", "location", "loc",
                    "_component", "model", "serial", "firmware", "notes",
                    "instances", "ports", "connectors"}

    def _iter_ifaces(ifaces_raw):
        """Yield (interface_type, iface_data) pairs from any ifaces format."""
        if isinstance(ifaces_raw, dict):
            yield from ifaces_raw.items()
        elif isinstance(ifaces_raw, list):
            for entry in ifaces_raw:
                if isinstance(entry, str):
                    yield entry, {}
                elif isinstance(entry, dict):
                    itype = entry.get("type") or entry.get("name")
                    if itype:
                        yield itype, entry
                    else:
                        for k, v in entry.items():
                            if k not in ("type", "name", "id", "location"):
                                yield k, v if isinstance(v, (dict, list)) else {}
        elif isinstance(ifaces_raw, str):
            yield ifaces_raw, {}

    def _iter_instances(iface_data):
        """Yield inst_dict from an interface value."""
        if isinstance(iface_data, dict):
            inst_list = (iface_data.get("instances") or
                         iface_data.get("ports") or
                         iface_data.get("connectors"))
            if inst_list is None:
                if any(k in iface_data for k in ("id", "name", "location", "loc")):
                    yield iface_data
                    return
                non_struct = {k: v for k, v in iface_data.items()
                              if k not in _STRUCTURAL}
                if non_struct:
                    for iname, idata in non_struct.items():
                        entry = dict(idata) if isinstance(idata, dict) else {}
                        entry.setdefault("name", iname)
                        entry.setdefault("location", iname)
                        yield entry
                    return
                # Only yield a default instance if iface_data is non-empty
                # (e.g. has structural-only keys like 'description').
                # An empty dict {} means "no instances" — yield nothing.
                if iface_data:
                    yield {}
                return
            if isinstance(inst_list, list):
                for item in inst_list:
                    if isinstance(item, str):
                        yield {"location": item}
                    elif isinstance(item, dict):
                        yield item
                    else:
                        yield {}
            return
        if isinstance(iface_data, list):
            for item in iface_data:
                if isinstance(item, str):
                    yield {"location": item}
                elif isinstance(item, dict):
                    yield item
        elif iface_data is None:
            yield {}

    def _add_instances(sd_key, sd_name, ifaces_raw):
        modules_list = INTERFACE_MODULES
        sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-') if sd_name else ''
        for interface, iface_data in _iter_ifaces(ifaces_raw):
            for inst_dict in _iter_instances(iface_data):
                inst_key = (inst_dict.get("id") or inst_dict.get("name") or
                            inst_dict.get("location") or inst_dict.get("loc") or
                            f"inst{len(instances)+1}")
                inst_key = str(inst_key).lower().replace(" ", "_")
                inst_loc = (inst_dict.get("location") or inst_dict.get("loc") or inst_key)
                modules  = modules_list.get(interface, [])
                instances.append({
                    'sd_key':       sd_key,
                    'sd_name':      sd_name,
                    'sd_dir':       sd_dir,
                    'interface':    interface,
                    'inst_key':     inst_key,
                    'inst_loc':     inst_loc,
                    'modules':      modules,
                    'module_count': len(modules),
                    'instance_id':  f"{sd_key}.{interface}.{inst_key}",
                })

    # ── Walk subdevices ────────────────────────────────────────────────────────
    raw_subdevices = yaml_data.get('subdevices')

    if isinstance(raw_subdevices, list):
        for sd in raw_subdevices:
            if isinstance(sd, str):
                sd = {"name": sd}
            if not isinstance(sd, dict):
                continue
            sd_key  = (sd.get("name") or "unknown").lower().replace(" ", "_")
            sd_name = sd.get("name") or "Unknown"
            ifaces  = sd.get("interfaces") or sd.get("interface")

            if ifaces is None:
                # Component-key pattern: {central_unit: {Ethernet: ...}, hand_unit: ...}
                for comp_key, comp_val in sd.items():
                    if comp_key in {"name", "id", "description"}:
                        continue
                    if isinstance(comp_val, dict):
                        comp_ifaces = {k: v for k, v in comp_val.items()
                                       if k in known_ifaces}
                        if comp_ifaces:
                            comp_sd_name = comp_key.replace("_", " ").title()
                            comp_sd_key  = comp_key.lower().replace(" ", "_")
                            _add_instances(comp_sd_key, comp_sd_name, comp_ifaces)
            else:
                _add_instances(sd_key, sd_name, ifaces)

    elif isinstance(raw_subdevices, dict):
        # Dict-keyed subdevices: {central_unit: {interfaces: {...}}, ...}
        for sd_key, sd_body in raw_subdevices.items():
            if isinstance(sd_body, dict):
                sd_name = sd_body.get("name") or sd_key.replace("_", " ").title()
                ifaces  = sd_body.get("interfaces") or sd_body.get("interface")
                if ifaces:
                    _add_instances(sd_key, sd_name, ifaces)

    return instances


# ── Photo-requirement virtual instances ──────────────────────────────────────

def collect_device_tool_photos(yaml_data: dict) -> list[dict]:
    """
    Return one virtual instance per unique interface type present in the project's
    subdevices.  Each maps to a single PHOTO-TOOLS-{Interface} module stored at
    project_dir/SHORT/device/_Tools/{interface_lower}/Photo/
    """
    # Gather unique interface types (preserve first-seen order, skip internals)
    seen: dict[str, str] = {}  # interface → inst_key
    for inst in collect_instances(yaml_data):
        iface = inst['interface']
        if iface not in seen and not iface.startswith('_'):
            seen[iface] = iface.lower().replace(' ', '_').replace('/', '-')

    result = []
    for iface, iface_key in seen.items():
        result.append({
            'sd_key':                '_device_',
            'sd_name':               '_Device_',
            'sd_dir':                '_Tools',
            'interface':             'Tools',
            'inst_key':              iface_key,
            'inst_loc':              iface,
            'modules':               [f'PHOTO-TOOLS-{iface}'],
            'module_count':          1,
            'instance_id':           f'_device_.Tools.{iface_key}',
            'is_device_tool_photo':  True,
            'tool_interface':        iface,
        })
    return result


def collect_subdevice_photos(yaml_data: dict) -> list[dict]:
    """
    Return three virtual instances per subdevice:
    PHOTO-{sd_dir}-FRONT, PHOTO-{sd_dir}-BACK, PHOTO-{sd_dir}-INTERFACES
    Stored at project_dir/SHORT/device/{sd_dir}/_Photos/{type}/Photo/
    """
    # Collect unique subdevices, preserving first-seen order
    seen_sds: dict[str, dict] = {}
    for inst in collect_instances(yaml_data):
        sd_key = inst['sd_key']
        if sd_key not in seen_sds:
            seen_sds[sd_key] = {'sd_name': inst['sd_name'], 'sd_dir': inst['sd_dir']}

    result = []
    for sd_key, info in seen_sds.items():
        sd_name = info['sd_name']
        sd_dir  = info['sd_dir']
        for photo_type in ('FRONT', 'BACK', 'INTERFACES'):
            type_lower  = photo_type.lower()
            module_name = f'PHOTO-{sd_dir}-{photo_type}'
            result.append({
                'sd_key':              sd_key,
                'sd_name':             sd_name,
                'sd_dir':              sd_dir,
                'interface':           '_photos_',
                'inst_key':            type_lower,
                'inst_loc':            photo_type.title(),
                'modules':             [module_name],
                'module_count':        1,
                'instance_id':         f'{sd_key}._photos_.{type_lower}',
                'is_subdevice_photo':  True,
                'photo_type':          photo_type,
            })
    return result


def collect_all_instances(yaml_data: dict) -> list[dict]:
    """collect_instances() plus device-tool and subdevice photo virtual instances."""
    instances = collect_instances(yaml_data)
    instances.extend(collect_device_tool_photos(yaml_data))
    instances.extend(collect_subdevice_photos(yaml_data))
    return instances


def compute_progress(yaml_data: dict, progress_data: dict,
                     active_project_id: str = None) -> dict:
    """
    Compute per-instance and per-module progress from gearbox progress JSON.
    Returns a dict keyed by "sd.iface.inst" with module statuses.

    Modules with status 'na' (port dead) are excluded from module_count so
    they don't inflate the total and the instance can still be marked complete.

    active_project_id: if provided and matches a currently-running gearbox,
    'running' status is preserved. Otherwise 'running' is treated as 'pending'
    (prevents stale running badges after gearbox exits).
    """
    module_status       = progress_data.get('module_status', {})
    completed_instances = set(progress_data.get('completed_instances', []))
    # Determine if gearbox is currently running so we know whether 'running' is live
    gearbox_live = active_project_id and active_project_id in _active_procs

    instances = collect_all_instances(yaml_data)
    result = {}

    for inst in instances:
        iid      = inst['instance_id']
        modules  = {}
        completed_count = 0
        counted_total   = 0
        all_terminal    = True

        for mod in inst['modules']:
            key    = f"{iid}.{mod}"
            raw    = module_status.get(key, {})
            status = raw.get('status', 'pending')
            detail = raw.get('detail', '')
            # Scrub stale 'running' — only show running when gearbox is live
            if status == 'running' and not gearbox_live:
                status = 'pending'
                detail = ''
            modules[mod] = {'status': status, 'detail': detail}

            if status == 'na':
                continue

            counted_total += 1

            if status == 'complete':
                completed_count += 1
            elif status not in ('complete', 'skipped'):
                all_terminal = False

        # Instance is complete only if the progress file says so AND our
        # local check agrees (guards against stale progress data)
        is_complete = (iid in completed_instances) and all_terminal

        result[iid] = {
            **inst,
            'module_statuses': modules,
            'completed':        is_complete,
            'completed_count':  completed_count,
            'module_count':     counted_total,   # N/A-excluded count
        }

    return result


# ─── Evidence content validators ─────────────────────────────────────────────

def _detect_tool_from_content(text: str, suffix: str) -> str | None:
    """
    Inspect file text to identify which tool produced it.
    Returns a tool key string or None if unrecognisable.
    """
    import re as _re
    # Nessus XML
    if suffix in ('.nessus', '.xml') and '<NessusClientData_v2' in text:
        return 'nessus_xml'
    # Nmap XML
    if suffix == '.xml' and '<nmaprun' in text:
        return 'nmap_xml'
    # sslscan
    if suffix == '.txt' and _re.search(r'Testing SSL server .+ on port', text):
        return 'sslscan'
    # testssl
    if suffix == '.txt' and _re.search(r'testssl\.sh|Start of testssl run|Testing protocols', text, _re.I):
        return 'testssl'
    # ssh-audit
    if suffix in ('.txt', '.json') and _re.search(r'ssh-audit|-- \[info\]|-- \[warn\]|-- \[fail\]|-- \[crit\]', text):
        return 'ssh_audit'
    # shcheck
    if suffix == '.txt' and _re.search(r'Checking security headers|X-Frame-Options|Content-Security-Policy', text):
        return 'shcheck'
    # nuclei
    if suffix == '.txt' and _re.search(r'\[[a-z-]+\] \[http\] \[(info|low|medium|high|critical)\]', text):
        return 'nuclei'
    # Nessus CSV
    if suffix == '.csv' and 'Plugin ID' in text and 'Risk' in text and 'Host' in text:
        return 'nessus_csv'
    # PCAP (binary — check magic bytes handled by caller)
    if suffix == '.pcap':
        return 'pcap'
    return None


# Module → list of (tool_key, validator_fn)
# validator_fn(text, suffix) -> bool: True = content looks valid for this tool
_TOOL_VALIDATORS: dict[str, list[tuple]] = {
    'Nessus': [
        ('nessus_xml', lambda t, s: s in ('.nessus', '.xml') and '<NessusClientData_v2' in t),
        ('nessus_csv', lambda t, s: s == '.csv' and 'Plugin ID' in t and 'Risk' in t),
    ],
    'NmapLive':  [('nmap_xml', lambda t, s: s == '.xml' and '<nmaprun' in t)],
    'NmapPort':  [('nmap_xml', lambda t, s: s == '.xml' and '<nmaprun' in t)],
    'Web': [
        ('sslscan',  lambda t, s: s == '.txt' and bool(re.search(r'Testing SSL server .+ on port', t))),
        ('testssl',  lambda t, s: s == '.txt' and bool(re.search(r'testssl|Testing protocols', t, re.I))),
        ('nuclei',   lambda t, s: s == '.txt' and bool(re.search(r'\[[a-z-]+\] \[http\]', t))),
        ('shcheck',  lambda t, s: s == '.txt' and bool(re.search(r'Checking security headers|X-Frame-Options', t))),
    ],
    'SSL': [
        ('sslscan',  lambda t, s: s == '.txt' and bool(re.search(r'Testing SSL server .+ on port', t))),
        ('testssl',  lambda t, s: s == '.txt' and bool(re.search(r'testssl|Testing protocols', t, re.I))),
        ('testssl_json', lambda t, s: s == '.json' and bool(re.search(r'"id".*"severity"', t))),
        ('shcheck',  lambda t, s: s == '.txt' and bool(re.search(r'Checking security headers|X-Frame-Options', t))),
    ],
    'SSH': [
        ('nmap_xml',  lambda t, s: s == '.xml' and '<nmaprun' in t),
        ('ssh_audit', lambda t, s: bool(re.search(r'ssh-audit|-- \[info\]|-- \[warn\]|-- \[fail\]', t))),
    ],
    'TrafficCollector': [
        ('pcap', lambda t, s: s == '.pcap'),
    ],
    'BannerGrab': [('banner_txt', lambda t, s: s == '.txt')],
    'Nuclei': [
        ('nuclei', lambda t, s: s == '.txt' and bool(re.search(r'\[[a-z-]+\] \[http\]', t))),
    ],
    'SMB':  [('nmap_xml', lambda t, s: s == '.xml' and '<nmaprun' in t)],
    'NFS':  [('nmap_xml', lambda t, s: s == '.xml' and '<nmaprun' in t)],
}


def _validate_upload_content(module: str, file_path: Path) -> tuple[bool, str]:
    """
    Check that an uploaded file:
      1. Has an extension accepted by MODULE_EVIDENCE for this module.
      2. Has contents consistent with a known tool for this module.

    Returns (ok, message).
    """
    suffix = file_path.suffix.lower()

    # Get accepted patterns
    entries    = MODULE_EVIDENCE.get(module, [])
    patterns   = []
    for e in entries:
        patterns.extend(e.get('patterns', []))

    import fnmatch as _fn
    if patterns:
        ext_ok = any(_fn.fnmatch(f'file{suffix}', p) for p in patterns)                  or any(_fn.fnmatch(file_path.name, p) for p in patterns)
        if not ext_ok:
            return False, (f"File type '{suffix}' is not expected for module "
                           f"'{module}'. Accepted patterns: {', '.join(patterns)}")

    # For binary files (pcap) skip text checks
    if suffix == '.pcap':
        if file_path.stat().st_size < 24:
            return False, "PCAP file appears empty or truncated."
        return True, "ok"

    # Read text
    try:
        text = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        return False, f"Could not read file: {e}"

    if not text.strip():
        return False, "File is empty."

    # Check content against known validators for this module
    validators = _TOOL_VALIDATORS.get(module, [])
    if validators:
        matched = any(fn(text, suffix) for _, fn in validators)
        if not matched:
            tool_names = [k for k, _ in validators]
            return False, (f"File contents do not appear to be output from any "
                           f"expected tool for module '{module}' "
                           f"({', '.join(tool_names)}). "
                           f"Please upload the correct output file.")

    return True, "ok"


def _run_upload_parser(module: str, file_path: Path, yaml_path: str, project_id: str) -> None:
    """
    Detect tool from file content, parse findings, emit via Socket.IO.
    Handles every module+tool combination.
    """
    try:
        suffix = file_path.suffix.lower()
        is_binary = suffix in ('.pcap',)
        text = '' if is_binary else file_path.read_text(encoding='utf-8', errors='replace')

        tool_key  = _detect_tool_from_content(text, suffix) or 'unknown'
        findings_out: list[dict] = []
        room = f"project_{project_id}"

        # ── Nessus XML ────────────────────────────────────────────────────
        if tool_key == 'nessus_xml':
            import xml.etree.ElementTree as ET
            RISK_MAP = {'4':'Critical','3':'High','2':'Medium','1':'Low','0':'Informational'}
            try:
                root = ET.parse(str(file_path)).getroot()
                for host in root.findall('.//ReportHost'):
                    ip = host.get('name', '')
                    for item in host.findall('ReportItem'):
                        sev  = item.get('severity', '0')
                        risk = RISK_MAP.get(sev, 'Informational')
                        if sev == '0':
                            continue
                        title = item.get('pluginName', 'Unknown Nessus Finding')
                        desc  = (item.findtext('description') or '')[:400]
                        cves  = [c.text for c in item.findall('cve') if c.text]
                        port  = item.get('port', '')
                        findings_out.append({
                            'title': title, 'description': desc,
                            'risk': risk, 'tool': 'nessus',
                            'ip': ip, 'port': port, 'cve_ids': cves,
                            'output_file': str(file_path), 'source': 'upload',
                        })
            except Exception as e:
                app.logger.warning(f"Nessus XML parse error: {e}")

        # ── Nessus CSV ────────────────────────────────────────────────────
        elif tool_key == 'nessus_csv':
            import csv as _csv
            RISK_MAP = {'Critical':'Critical','High':'High','Medium':'Medium',
                        'Low':'Low','None':'Informational','Info':'Informational'}
            try:
                reader = _csv.DictReader(text.splitlines())
                for row in reader:
                    risk  = RISK_MAP.get(row.get('Risk', 'None'), 'Informational')
                    title = row.get('Name', 'Unknown')
                    desc  = row.get('Description', '')[:400]
                    ip    = row.get('Host', '')
                    port  = row.get('Port', '')
                    cve_s = row.get('CVE', '')
                    cves  = [c.strip() for c in cve_s.split(',') if c.strip()]
                    if risk == 'Informational':
                        continue
                    findings_out.append({
                        'title': title, 'description': desc,
                        'risk': risk, 'tool': 'nessus',
                        'ip': ip, 'port': port, 'cve_ids': cves,
                        'output_file': str(file_path), 'source': 'upload',
                    })
            except Exception as e:
                app.logger.warning(f"Nessus CSV parse error: {e}")

        # ── sslscan ───────────────────────────────────────────────────────
        elif tool_key == 'sslscan':
            url_m = re.search(r'Testing SSL server\s+(\S+)\s+on port\s+(\d+)', text, re.I)
            tip   = url_m.group(1) if url_m else ''
            tprt  = url_m.group(2) if url_m else ''
            url   = f"https://{tip}:{tprt}" if tip else ''
            CHECKS = [
                (r'SSLv2\s+enabled',    None,   'SSLv2 Enabled', 'High'),
                (r'SSLv3\s+enabled',    None,   'SSLv3 Enabled', 'Medium'),
                (r'TLSv1\.0\s+enabled', None,   'TLS 1.0 Enabled', 'Low'),
                (r'TLSv1\.1\s+enabled', None,   'TLS 1.1 Enabled', 'Low'),
                (r'RC4\s+cipher',       r'not\s+vuln|disabled',
                 'SSL/TLS — Weak Encryption Method (RC4)', 'High'),
                (r'EXPORT\s+cipher',    r'not\s+vuln|disabled',
                 'SSL/TLS — Weak Encryption Method (Export)', 'High'),
                (r'Heartbleed',         r'not\s+vuln|not\s+affect|N/A|disabled|secure|Heartbleed\s*:\s*$',
                 'Heartbleed (CVE-2014-0160)', 'Critical'),
            ]
            for line in text.splitlines():
                for pos_pat, neg_pat, label, risk in CHECKS:
                    if not re.search(pos_pat, line, re.I): continue
                    if neg_pat and re.search(neg_pat, line, re.I): continue
                    findings_out.append({
                        'title': f"SSL/TLS — {label} ({url})",
                        'description': f"sslscan (uploaded): {line.strip()}",
                        'risk': risk, 'tool': 'sslscan',
                        'ip': tip, 'port': tprt, 'cve_ids': [],
                        'output_file': str(file_path), 'source': 'upload',
                    })
                    break

        # ── testssl ───────────────────────────────────────────────────────
        elif tool_key == 'testssl':
            RISK_MAP = {'critical':'Critical','severe':'Critical','high':'High',
                        'medium':'Medium','warn':'Low','low':'Low'}
            finding_re = re.compile(r'^\s*(CRITICAL|SEVERE|HIGH|MEDIUM|WARN|LOW)\s+(.+)', re.I)
            skip_re    = re.compile(r'not\s+vuln|not\s+offer|not\s+affect|not\s+tested|benign', re.I)
            url_m = re.search(r'Testing\s+(https?://\S+)', text, re.I)
            url   = url_m.group(1).rstrip('/') if url_m else ''
            _u    = re.match(r'https?://([^/:]+)(?::(\d+))?', url) if url else None
            tip   = _u.group(1) if _u else ''
            tprt  = (_u.group(2) if (_u and _u.group(2)) else '443') if _u else ''
            for line in text.splitlines():
                m = finding_re.match(line)
                if not m: continue
                sev  = m.group(1).lower(); desc = m.group(2).strip()
                if skip_re.search(desc) or len(desc) < 4: continue
                risk = RISK_MAP.get(sev, 'Medium')
                cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d+', desc, re.I)]
                findings_out.append({
                    'title': f"SSL/TLS — {desc[:80]} ({url})",
                    'description': f"testssl.sh (uploaded): {desc}",
                    'risk': risk, 'tool': 'testssl.sh',
                    'ip': tip, 'port': tprt, 'cve_ids': cves,
                    'output_file': str(file_path), 'source': 'upload',
                })

        # ── testssl JSON ──────────────────────────────────────────────────
        elif tool_key == 'testssl_json':
            import json as _json
            RISK_MAP = {'CRITICAL':'Critical','SEVERE':'Critical','HIGH':'High',
                        'MEDIUM':'Medium','WARN':'Low','LOW':'Low'}
            try:
                data = _json.loads(text)
                entries = data if isinstance(data, list) else data.get('findings', [])
                for entry in entries:
                    sev  = str(entry.get('severity', '')).upper()
                    if sev in ('OK', 'INFO', 'NOT_TESTED') or not sev: continue
                    desc = entry.get('finding', '')
                    if re.search(r'not\s+vuln|not\s+offer', desc, re.I): continue
                    risk = RISK_MAP.get(sev, 'Medium')
                    cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d+', desc, re.I)]
                    findings_out.append({
                        'title': f"SSL/TLS — {desc[:80]}",
                        'description': f"testssl.sh JSON (uploaded): {desc}",
                        'risk': risk, 'tool': 'testssl.sh',
                        'ip': '', 'port': '', 'cve_ids': cves,
                        'output_file': str(file_path), 'source': 'upload',
                    })
            except Exception as e:
                app.logger.warning(f"testssl JSON parse error: {e}")

        # ── ssh-audit ─────────────────────────────────────────────────────
        elif tool_key == 'ssh_audit':
            RISK_MAP = {'crit':'Critical','fail':'High','warn':'Medium','info':'Informational'}
            sev_re = re.compile(r'--\s+\[(crit|fail|warn|info)\]\s+(.+)', re.I)
            ip_m   = re.search(r'#\s+(\d+\.\d+\.\d+\.\d+):(\d+)', text)
            tip    = ip_m.group(1) if ip_m else ''
            tprt   = ip_m.group(2) if ip_m else '22'
            for line in text.splitlines():
                m = sev_re.search(line)
                if not m: continue
                sev  = m.group(1).lower(); desc = m.group(2).strip()
                risk = RISK_MAP.get(sev[:4], 'Informational')
                if risk == 'Informational': continue
                cves = [c.upper() for c in re.findall(r'CVE-\d{4}-\d+', desc, re.I)]
                findings_out.append({
                    'title': f"SSH Configuration Issue — {tip}:{tprt}",
                    'description': f"ssh-audit (uploaded): {desc}",
                    'risk': risk, 'tool': 'ssh-audit',
                    'ip': tip, 'port': tprt, 'cve_ids': cves,
                    'output_file': str(file_path), 'source': 'upload',
                })

        # ── shcheck ───────────────────────────────────────────────────────
        elif tool_key == 'shcheck':
            missing_re = re.compile(r'Header\s+([\w\-]+)\s+is not present', re.I)
            url_m = re.search(r'Checking\s+(https?://\S+)', text, re.I)
            url   = url_m.group(1) if url_m else ''
            _u    = re.match(r'https?://([^/:]+)(?::(\d+))?', url) if url else None
            tip   = _u.group(1) if _u else ''
            tprt  = (_u.group(2) if _u and _u.group(2) else '443') if _u else ''
            for header in missing_re.findall(text):
                findings_out.append({
                    'title': f"Missing Security Header: {header} ({url})",
                    'description': f"shcheck (uploaded): {header} is missing on {url}.",
                    'risk': 'Low', 'tool': 'shcheck',
                    'ip': tip, 'port': tprt, 'cve_ids': [],
                    'output_file': str(file_path), 'source': 'upload',
                })

        # ── nuclei ────────────────────────────────────────────────────────
        elif tool_key == 'nuclei':
            risk_map = {'info':'Informational','low':'Low','medium':'Medium',
                        'high':'High','critical':'Critical'}
            line_re  = re.compile(
                r'\[([^\]]+)\]\s+\[http\]\s+\[(info|low|medium|high|critical)\]\s+(\S+)', re.I)
            for line in text.splitlines():
                m = line_re.search(line)
                if not m: continue
                tmpl = m.group(1); sev = m.group(2).lower(); target = m.group(3)
                risk = risk_map.get(sev, 'Informational')
                host_m = re.match(r'https?://([^/:]+)(?::(\d+))?', target)
                tip    = host_m.group(1) if host_m else ''
                tprt   = (host_m.group(2) if host_m and host_m.group(2) else
                          ('443' if target.startswith('https') else '80'))
                cves   = [c.upper() for c in re.findall(r'CVE-\d{4}-\d+', line, re.I)]
                findings_out.append({
                    'title': f"Nuclei: {tmpl} ({tip}:{tprt})",
                    'description': f"nuclei (uploaded): {line.strip()}",
                    'risk': risk, 'tool': 'nuclei',
                    'ip': tip, 'port': tprt, 'cve_ids': cves,
                    'output_file': str(file_path), 'source': 'upload',
                })

        # ── nmap XML ─────────────────────────────────────────────────────
        elif tool_key == 'nmap_xml':
            pass   # nmap XML produces hosts/ports (DB-level) not findings; skip for now

        # ── Emit findings ─────────────────────────────────────────────────
        if findings_out:
            import uuid as _uuid, time as _time
            for fd in findings_out:
                fd.setdefault('id',             str(_uuid.uuid4()))
                fd.setdefault('timestamp',      str(_time.time()))
                fd.setdefault('classification', 'Network Security')
                fd.setdefault('output_files',   [fd.get('output_file', '')])
                socketio.emit('new_finding', fd, room=room)
            app.logger.info(
                f"Upload parser emitted {len(findings_out)} findings "
                f"(module={module}, tool={tool_key})")

        # ── Mark module complete after successful upload + parse ────────────
        # Applies to any module whose evidence was uploaded and parsed cleanly.
        # We update progress.json and emit a live module_status event so the
        # evidence tab badge updates without requiring a page reload.
        try:
            _prog = load_progress(yaml_path)
            _ms   = _prog.setdefault('module_status', {})
            # Derive instance key from yaml_path directory name convention.
            # The file_path parent structure is: .../<SD>/<Iface>/<Inst>/<Module>/
            _parts = list(file_path.parts)
            # Walk upward looking for the module dir name matching `module`
            _detail = f"Evidence uploaded and parsed — {len(findings_out)} finding(s) extracted"
            if not findings_out:
                _detail = "Evidence uploaded and validated"
            # Build mod_key from file_path: locate module subdir in path
            _module_dir_idx = next(
                (i for i, p in enumerate(_parts) if p == module), None)
            if _module_dir_idx is not None and _module_dir_idx >= 3:
                _inst    = _parts[_module_dir_idx - 1]
                _iface   = _parts[_module_dir_idx - 2]
                _sd      = _parts[_module_dir_idx - 3]
                # Normalise subdevice dir → key by lowercasing & replacing spaces
                _yaml    = load_yaml(yaml_path)
                _sd_key  = next(
                    (k for k, v in _yaml.get('subdevices', {}).items()
                     if (v.get('name', k).replace(' ','_') == _sd
                         or k == _sd.lower()
                         or k.replace('_',' ').title().replace(' ','_') == _sd)),
                    _sd.lower())
                _iid     = f"{_sd_key}.{_iface}.{_inst}"
                _mod_key = f"{_iid}.{module}"
                _ms[_mod_key] = {
                    'status':    'complete',
                    'detail':    _detail,
                    'timestamp': datetime.now().isoformat(),
                }
                _progress_file = Path(os.path.dirname(os.path.abspath(yaml_path))) / 'progress.json'
                with open(str(_progress_file), 'w', encoding='utf-8') as _pf:
                    json.dump(_prog, _pf, indent=2)
                socketio.emit('module_status', {
                    'subdevice': _sd_key,
                    'interface': _iface,
                    'instance':  _inst,
                    'module':    module,
                    'status':    'complete',
                    'detail':    _detail,
                }, room=room)
                app.logger.info(f"Module {_mod_key} marked complete after upload")
        except Exception as _me:
            app.logger.warning(f"Could not mark module complete after upload: {_me}")

    except Exception as e:
        app.logger.warning(f"_run_upload_parser failed for {module}: {e}")


def load_findings(yaml_path: str) -> list[dict]:
    """Load findings from gearbox findings.jsonl, deduplicated by id (last write wins)."""
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    project_dir   = os.path.dirname(os.path.abspath(yaml_path))
    findings_file = os.path.join(project_dir, 'findings.jsonl')
    if not os.path.exists(findings_file):
        return []
    # Use an ordered dict keyed by id so the last occurrence of each id wins.
    # Findings without an id are kept as-is (should not occur in practice).
    seen: dict = {}   # id -> dict
    no_id: list = []
    try:
        with open(findings_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    # Normalise output_files
                    files   = d.get('output_files', [])
                    if not isinstance(files, list):
                        files = [files] if files else []
                    primary = d.get('output_file', '')
                    if primary and primary not in files:
                        files.insert(0, primary)
                    d['output_files'] = files
                    d['output_file']  = files[0] if files else ''
                    fid = d.get('id')
                    if fid:
                        seen[fid] = d   # overwrite → last occurrence wins
                    else:
                        no_id.append(d)
                except Exception:
                    pass
    except Exception:
        pass
    return list(seen.values()) + no_id


def count_modules(yaml_data: dict, progress_data: dict) -> tuple[int, int]:
    """Return (completed, total) module counts, excluding N/A modules."""
    progress_map = compute_progress(yaml_data, progress_data)
    total     = sum(inst['module_count'] for inst in progress_map.values())
    completed = sum(inst['completed_count'] for inst in progress_map.values())
    return completed, total



# ─── Module Evidence Registry ───────────────────────────────────────────────
#
# For each module, defines the minimum evidence that must exist on disk to
# consider the module genuinely complete.  Each entry is a dict:
#
#   subdir     – subdirectory inside the instance dir ('' = instance dir itself)
#   patterns   – list of glob patterns; at least ONE file matching ANY pattern
#                must exist.  '*' = any file at all.
#   photo_only – if True, this evidence entry only applies to the Photo module
#                and the status 'skipped' is always treated as invalid (a photo
#                must be physically captured to count as evidence).
#
# Modules where skipped IS acceptable evidence (hardware not present):
#   Keyboard, Mouse, BashBunny, HdmiCEC, NFS, SMB (no shares), SSH (no ports),
#   Web (no web services), Nessus (--skip-nessus), NmapPort (no live hosts),
#   BannerGrab (no hosts), CanReplay, RFIDReplay, Flood
#
# Photo is NEVER acceptable as skipped — see gearbox.py PhotoModule.
# ────────────────────────────────────────────────────────────────────────────
MODULE_EVIDENCE: dict[str, list[dict]] = {
    # ── Photo ───────────────────────────────────────────────────────────────
    'Photo': [
        {'subdir': 'Photo', 'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True},
    ],

    # ── Ethernet ─────────────────────────────────────────────────────────────
    'Ethtool': [
        # Gearbox writes {file_prefix}_ethtool.txt directly in instance_dir
        {'subdir': '', 'patterns': ['*ethtool*.txt']},
    ],
    'EthtoolConnectedPhoto': [
        {'subdir': 'EthtoolConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'ConfigDiscovery': [
        {'subdir': 'ConfigDiscovery',
         'patterns': ['config_discovery_log.txt', '*.pcap', '*.txt'],
         'skip_ok': True},
    ],
    'TrafficCollector': [
        {'subdir': 'TrafficCollector', 'patterns': ['*tcpdump*.pcap', '*tshark*.pcap', '*tshark*summary*.txt'],
         'skip_ok': True},
    ],
    'NmapLive': [
        {'subdir': 'NmapLive', 'patterns': ['*.xml', '*.txt', '*.nmap'],
         'skip_ok': True},
    ],
    'Nessus': [
        {'subdir': 'Nessus', 'patterns': ['*.csv', '*.nessus', '*.html'],
         'skip_ok': True},
    ],
    'Responder': [
        {'subdir': 'Responder', 'patterns': ['*hashes*.txt', '*credentials*.txt',
                                              'logs/*.log'],
         'skip_ok': True},
    ],
    'NmapPort': [
        {'subdir': 'NmapPort', 'patterns': ['*.xml', '*.txt', '*.nmap'],
         'skip_ok': True},
    ],
    'BannerGrab': [
        {'subdir': 'BannerGrab', 'patterns': ['*banner*.txt', '*.txt'],
         'skip_ok': True},
    ],
    'Web': [
        {'subdir': 'Web', 'patterns': ['targets.txt', '*.html', '*.txt'],
         'skip_ok': True},
        {'subdir': 'Web/screenshots',
         'patterns': ['*.png', '*.jpg', '*.jpeg', '*.webp'],
         'skip_ok': True, 'photo_only': True},
    ],
    'Nuclei': [
        {'subdir': 'Nuclei',
         'patterns': ['*_nuclei.txt', 'nuclei_bulk.txt', 'targets.txt'],
         'skip_ok': True},
    ],
    'SSH': [
        {'subdir': 'SSH', 'patterns': ['*nmap_ssh*.txt', '*ssh_audit*.txt', '*ssh_audit*.json'],
         'skip_ok': True},
    ],
    'SSL': [
        {'subdir': 'SSL',
         'patterns': ['*_sslscan.txt', '*_testssl.txt', '*_testssl.json', '*_shcheck.txt'],
         'skip_ok': True},
    ],
    'SMB': [
        {'subdir': 'SMB', 'patterns': ['*nmap_smb*.txt', '*responder*.log', '*.txt'],
         'skip_ok': True},
    ],
    'NFS': [
        {'subdir': 'NFS', 'patterns': ['*nfs*.txt', '*.txt'],
         'skip_ok': True},
    ],
    'FTP': [
        {'subdir': 'FTP', 'patterns': ['*ftp*.txt', '*.txt'],
         'skip_ok': True},
    ],

    # ── USB ──────────────────────────────────────────────────────────────────
    'UsbPower': [
        {'subdir': 'UsbPower', 'patterns': ['*usb_power*.txt', '*.txt'],
         'skip_ok': True},
    ],
    'UsbPowerConnectedPhoto': [
        {'subdir': 'UsbPowerConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'Keyboard': [
        {'subdir': 'Keyboard', 'patterns': ['*keyboard*.txt'],
         'skip_ok': True},
    ],
    'KeyboardConnectedPhoto': [
        {'subdir': 'KeyboardConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'KeyCombos': [
        {'subdir': 'KeyCombos', 'patterns': ['*keycombos*.txt', '*.txt'],
         'skip_ok': True},
    ],
    'Mouse': [
        {'subdir': 'Mouse', 'patterns': ['*mouse*.txt'],
         'skip_ok': True},
    ],
    'MouseConnectedPhoto': [
        {'subdir': 'MouseConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'BashBunny': [
        {'subdir': 'BashBunny', 'patterns': ['*bashbunny*.txt'],
         'skip_ok': True},
    ],
    'BashBunnyConnectedPhoto': [
        {'subdir': 'BashBunnyConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],

    # ── Ethernet tap ─────────────────────────────────────────────────────────
    # Gearbox writes to Tcpdump_running/, Tcpdump_boot/, Tcpdump_shutdown/
    'Tcpdump_running': [
        {'subdir': 'Tcpdump_running', 'patterns': ['*.pcap']},
    ],
    'Tcpdump_runningConnectedPhoto': [
        {'subdir': 'Tcpdump_runningConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'Tcpdump_boot': [
        {'subdir': 'Tcpdump_boot', 'patterns': ['*.pcap']},
    ],
    'Tcpdump_bootConnectedPhoto': [
        {'subdir': 'Tcpdump_bootConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'Tcpdump_shutdown': [
        {'subdir': 'Tcpdump_shutdown', 'patterns': ['*.pcap']},
    ],

    # ── Video/audio interfaces ────────────────────────────────────────────────
    # Gearbox uses Input/ and Output/ (not VideoInput/VideoOutput)
    'PortType': [
        {'subdir': 'PortType', 'patterns': ['*port_type*.txt']},
    ],
    'Input': [
        {'subdir': 'Input', 'patterns': ['*input*.txt']},
    ],
    'InputConnectedPhoto': [
        {'subdir': 'InputConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'Output': [
        {'subdir': 'Output', 'patterns': ['*output*.txt']},
    ],
    'OutputConnectedPhoto': [
        {'subdir': 'OutputConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'EDID': [
        {'subdir': 'EDID', 'patterns': ['*edid*.bin', '*edid*.txt']},
    ],
    'HdmiDDC': [
        {'subdir': 'HdmiDDC', 'patterns': ['*_ddc_detect.txt', '*_ddc_capabilities.txt',
                                            '*_ddc_vcpinfo.txt', '*_ddc_note.txt']},
    ],
    'HdmiHDCP': [
        {'subdir': 'HdmiHDCP', 'patterns': ['*hdcp*.txt'],
         'skip_ok': True},
    ],
    'HdmiCEC': [
        {'subdir': 'HdmiCEC', 'patterns': ['*cec*.txt', '*.txt'],
         'skip_ok': True},
    ],
    'HdmiCECConnectedPhoto': [
        {'subdir': 'HdmiCECConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],

    # ── Zigbee ───────────────────────────────────────────────────────────────
    'Sniff': [
        {'subdir': 'Sniff', 'patterns': ['*.pcap', '*.txt']},
    ],
    'SniffConnectedPhoto': [
        {'subdir': 'SniffConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'Flood': [
        {'subdir': 'Flood', 'patterns': ['*.txt'],
         'skip_ok': True},
    ],

    # ── DB9 / Serial ─────────────────────────────────────────────────────────
    'SerialDetect': [
        {'subdir': 'SerialDetect', 'patterns': ['*.txt'],
         'skip_ok': True},
    ],
    'SerialDetectConnectedPhoto': [
        {'subdir': 'SerialDetectConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'CanAssess': [
        {'subdir': 'CanAssess', 'patterns': ['*.txt', '*.log'],
         'skip_ok': True},
    ],
    'CanAssessConnectedPhoto': [
        {'subdir': 'CanAssessConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],

    # ── RFID ─────────────────────────────────────────────────────────────────
    'RFIDSniff': [
        {'subdir': 'RFIDSniff', 'patterns': ['*.txt'],
         'skip_ok': True},
    ],
    'RFIDSniffConnectedPhoto': [
        {'subdir': 'RFIDSniffConnectedPhoto',
         'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
         'photo_only': True, 'skip_ok': True},
    ],
    'RFIDReplay': [
        {'subdir': 'RFIDReplay', 'patterns': ['*.txt'],
         'skip_ok': True},
    ],
}

# Modules where a 'skipped' status in progress is always evidence of completion
# (hardware was absent or not applicable — no files required)
SKIP_ACCEPTABLE = {
    mod for mod, entries in MODULE_EVIDENCE.items()
    if any(e.get('skip_ok') for e in entries)
}

# Photo is NEVER acceptable as skipped
PHOTO_SKIP_INVALID = {'Photo'}

# Runtime helper — returns evidence entries for any module, including dynamic PHOTO-* ones
_PHOTO_EVIDENCE_ENTRY = [
    {'subdir': 'Photo',
     'patterns': ['*.jpg', '*.jpeg', '*.png', '*.webp', '*.gif'],
     'photo_only': True}
]

def _mod_evidence(module: str) -> list[dict]:
    """Return MODULE_EVIDENCE entries for module; PHOTO-* falls back to photo definition."""
    if module in MODULE_EVIDENCE:
        return MODULE_EVIDENCE[module]
    if module.startswith('PHOTO-'):
        return _PHOTO_EVIDENCE_ENTRY
    return []

def _is_photo_module(module: str) -> bool:
    """True for the built-in Photo module and all dynamic PHOTO-* modules."""
    return module == 'Photo' or module.startswith('PHOTO-')

# Modules that complete without requiring evidence files.
# Responder may run without capturing anything.
# ConfigDiscovery writes a log but older runs may not have it.
NO_EVIDENCE_REQUIRED = {
    # Passive / orchestration modules that run without producing evidence files
    'Responder', 'ConfigDiscovery', 'TrafficCollector',
    'EthernetIface', 'DhcpServer', 'EthernetCleanup',
    # Phase-2 per-host modules that complete with 'N/A No X Ports' when
    # no relevant ports are discovered — no files are created in that case.
    # When ports ARE found the module runs normally and produces files, but
    # completion must never be reverted by a missing-evidence check.
    'FTP', 'SSH', 'SSL', 'SMB', 'NFS', 'BannerGrab',
    'Web', 'Nuclei',
}


def _instance_dir(yaml_data: dict, yaml_path: str,
                  sd_key: str, sd_name: str,
                  interface: str, inst_key: str) -> Path:
    """Reconstruct the instance directory path matching gearbox.py's layout.
    Structure: project_dir / CLIENT_SHORT / device / sd_name / interface / inst_key
    Special:
      _device_ / Tools / {iface_lower}  →  …/_Tools/{iface_lower}
      {sd_key} / _photos_ / {type}      →  …/{sd_dir}/_Photos/{type}
    """
    project_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))
    short  = (yaml_data.get('client_short') or 'proj').strip().replace(' ', '_').upper()
    device = (yaml_data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')

    if sd_key == '_device_' and interface == 'Tools':
        return project_dir / short / device / '_Tools' / inst_key

    sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-') if sd_name else ''

    if interface == '_photos_':
        if sd_dir:
            return project_dir / short / device / sd_dir / '_Photos' / inst_key
        return project_dir / short / device / '_Photos' / inst_key

    if sd_dir:
        return project_dir / short / device / sd_dir / interface / inst_key
    return project_dir / short / device / interface / inst_key


def _evidence_present(inst_dir: Path, evidence_entries: list[dict]) -> bool:
    """Return True if at least one matching evidence file exists."""
    import fnmatch
    for entry in evidence_entries:
        subdir   = entry.get('subdir', '')
        patterns = entry.get('patterns', ['*'])
        search   = inst_dir / subdir if subdir else inst_dir
        if not search.exists():
            continue
        for f in search.rglob('*'):
            if not f.is_file():
                continue
            if any(fnmatch.fnmatch(f.name, p) for p in patterns):
                return True
    return False


def _module_needs_reset(mod: str, status: str, inst_dir: Path) -> tuple[bool, str]:
    """Decide whether a module should be reset. Returns (should_reset, reason)."""
    # All photo modules (Photo + PHOTO-*) cannot be skipped
    if _is_photo_module(mod) and status == 'skipped':
        return True, 'Photo was skipped — a photo must be captured'
    # Not in a terminal state — not our concern
    if status not in ('complete', 'skipped'):
        return False, ''
    # Skipped + skip acceptable -> no files required
    if status == 'skipped' and mod in SKIP_ACCEPTABLE:
        return False, ''
    # Skipped + skip NOT acceptable -> treat as missing
    if status == 'skipped' and mod not in SKIP_ACCEPTABLE:
        return True, f'{mod} was skipped but skipping is not permitted for this module'
    # Complete -> verify evidence files (skip for evidence-free modules)
    if mod in NO_EVIDENCE_REQUIRED:
        return False, ''
    evidence = _mod_evidence(mod)
    if not evidence:
        return False, ''
    if not _evidence_present(inst_dir, evidence):
        return True, f'No evidence files found for {mod}'
    return False, ''


def verify_module_files(yaml_data: dict, yaml_path: str,
                        progress_data: dict) -> tuple[dict, list[str]]:
    """
    Walk every module that claims to be complete or skipped.  Verify evidence
    rules.  Reset modules with missing/invalid evidence, archive their output,
    and recompute instance-level completion.
    """
    project_dir         = Path(os.path.dirname(os.path.abspath(yaml_path)))
    deleted_base        = project_dir / 'deleted'
    module_status       = progress_data.get('module_status', {})
    completed_instances = set(progress_data.get('completed_instances', []))
    resets: list[str]   = []
    changed             = False

    instances = collect_all_instances(yaml_data)
    for inst in instances:
        sd_key   = inst['sd_key']
        sd_name  = inst['sd_name']
        iface    = inst['interface']
        inst_key = inst['inst_key']
        iid      = inst['instance_id']

        inst_dir = _instance_dir(
            yaml_data, yaml_path, sd_key, sd_name, iface, inst_key)

        instance_needs_recheck = False

        for mod in inst['modules']:
            mod_key = f'{iid}.{mod}'
            status  = module_status.get(mod_key, {}).get('status', 'pending')

            should_reset, reason = _module_needs_reset(mod, status, inst_dir)
            if not should_reset:
                continue

            # Archive existing module output
            ts_tag       = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_name = f'{sd_name}__{iface}__{inst_key}__{mod}__{ts_tag}'
            archive_dir  = deleted_base / archive_name
            moved        = False

            for entry in _mod_evidence(mod):
                subdir = entry.get('subdir', '')
                src    = inst_dir / subdir if subdir else inst_dir
                if src.exists() and src != inst_dir:
                    try:
                        archive_dir.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(src), str(archive_dir / (subdir or mod)))
                        moved = True
                    except Exception:
                        pass

            module_status[mod_key] = {
                'status':    'pending',
                'detail':    f'Reset ({ts_tag}): {reason}',
                'timestamp': datetime.now().isoformat(),
            }
            instance_needs_recheck = True
            changed = True
            resets.append(
                f'{sd_name} / {iface} / {inst_key} — {mod}: {reason}'
                + (f' (archived -> deleted/{archive_name})' if moved else '')
            )

        # Recompute instance completion unconditionally — catches the case where
        # modules are individually marked complete via evidence uploads but the
        # instance was never formally added to completed_instances (e.g. Photo
        # was uploaded first, other modules were pending → instance was removed,
        # but subsequent uploads never re-triggered the completion check).
        all_ok = True
        for mod in inst['modules']:
            mod_key = f'{iid}.{mod}'
            s       = module_status.get(mod_key, {}).get('status', 'pending')
            # Photo must be captured — skipped/error/pending all disqualify
            if _is_photo_module(mod) and s != 'complete':
                all_ok = False
                break
            # All other modules: complete is ideal; skipped is acceptable
            # for hardware-absent scenarios; na means port dead / not applicable
            if s not in ('complete', 'skipped', 'na'):
                all_ok = False
                break
        if all_ok and iid not in completed_instances:
            completed_instances.add(iid)
            changed = True
        elif not all_ok and iid in completed_instances:
            completed_instances.discard(iid)
            changed = True

    if changed:
        progress_data['module_status']       = module_status
        progress_data['completed_instances'] = list(completed_instances)
        progress_file = os.path.join(
            os.path.dirname(os.path.abspath(yaml_path)), 'progress.json')
        try:
            with open(progress_file, 'w', encoding='utf-8') as f:
                json.dump(progress_data, f, indent=2)
        except Exception:
            pass

    return progress_data, resets


def enrich_project(project_info: dict) -> dict | None:
    """Load YAML + progress + findings and return enriched project dict, or None on error."""
    yaml_path = project_info.get('yaml_path', '')
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    if not os.path.exists(yaml_path):
        return None
    try:
        yaml_data = load_yaml(yaml_path)
    except Exception:
        return None

    # Transparently migrate any auto-generated instance/subdevice keys to user-defined names
    yaml_data, key_migrations = migrate_yaml_instance_keys(yaml_path)
    if key_migrations:
        # Reload in case migration rewrote the file
        try:
            yaml_data = load_yaml(yaml_path)
        except Exception:
            pass

    progress_data = load_progress(yaml_path)

    # If gearbox is actively running for this project, trust the live in-memory
    # progress entirely — do NOT run verify_module_files which would reset
    # modules that appear complete but whose files are mid-write.
    gearbox_running = project_info.get('id', '') in _active_procs
    if gearbox_running:
        integrity_resets = []
    else:
        # Only verify file existence if the project has evidence subdirectories.
        # If the project dir only contains root files (no instance output dirs),
        # verification would incorrectly reset all completed module statuses.
        _proj_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))
        _has_evidence_dirs = any(
            d.is_dir() for d in _proj_dir.iterdir()
            if d.name not in ('deleted', '__pycache__', '.git', '.DS_Store')
        )
        if _has_evidence_dirs:
            progress_data, integrity_resets = verify_module_files(
                yaml_data, yaml_path, progress_data)
        else:
            integrity_resets = []

    # Only load the findings count + risk breakdown for the template.
    # Full findings data is fetched on demand by the Findings tab JS.
    _all_findings = load_findings(yaml_path)
    findings_count = len(_all_findings)
    findings_risk_counts: dict[str, int] = {}
    for f in _all_findings:
        risk = f.get('risk', 'Unknown')
        findings_risk_counts[risk] = findings_risk_counts.get(risk, 0) + 1
    del _all_findings  # free memory — template doesn't need the full list
    findings = []      # empty list keeps template logic that checks `if findings` working

    # Cheap targets count: just count rows in discovered_hosts table
    targets_count = 0
    try:
        import sqlite3 as _sq3
        _proj_dir_t = Path(os.path.dirname(os.path.abspath(yaml_path)))
        _stem       = Path(yaml_path).stem
        _db         = _proj_dir_t / f'{_stem}.db'
        if not _db.exists():
            _dbs = sorted(_proj_dir_t.glob('*.db')) + sorted(_proj_dir_t.glob('*/*.db'))
            _db  = _dbs[0] if _dbs else None
        if _db and _db.exists():
            _conn = _sq3.connect(str(_db), timeout=5)
            targets_count = _conn.execute(
                'SELECT COUNT(DISTINCT ip) FROM discovered_hosts').fetchone()[0]
            _conn.close()
    except Exception:
        pass
    completed, total = count_modules(yaml_data, progress_data)
    progress_map     = compute_progress(yaml_data, progress_data,
                                    active_project_id=project_info.get("id",""))

    # ── Photo-module progress for Evidence tab sections ───────────────────────
    _mod_stat     = progress_data.get('module_status', {})
    _gbox_running = project_info.get('id', '') in _active_procs

    def _photo_status(iid: str, module: str) -> dict:
        raw    = _mod_stat.get(f'{iid}.{module}', {})
        status = raw.get('status', 'pending')
        if status == 'running' and not _gbox_running:
            status = 'pending'
        return {'status': status, 'detail': raw.get('detail', '')}

    device_tool_photos = []
    for _inst in collect_device_tool_photos(yaml_data):
        _mod = _inst['modules'][0]
        device_tool_photos.append({**_inst, **_photo_status(_inst['instance_id'], _mod)})

    subdevice_photos_by_sd: dict[str, list] = {}
    for _inst in collect_subdevice_photos(yaml_data):
        _sd  = _inst['sd_key']
        _mod = _inst['modules'][0]
        subdevice_photos_by_sd.setdefault(_sd, []).append(
            {**_inst, **_photo_status(_inst['instance_id'], _mod)}
        )

    return {
        **project_info,
        'yaml':                   yaml_data,
        'progress':               progress_data,
        'progress_map':           progress_map,
        'findings':               findings,
        'findings_count':         findings_count,
        'findings_risk_counts':   findings_risk_counts,
        'targets_count':          targets_count,
        'total_modules':          total,
        'completed_modules':      completed,
        'integrity_resets':       integrity_resets,
        'device_tool_photos':     device_tool_photos,
        'subdevice_photos_by_sd': subdevice_photos_by_sd,
    }


# ─── Routes ────────────────────────────────────────────────────────────────────





def _pcap_to_text(pcap_path: str) -> str:
    """Parse a pcap/pcapng file with dpkt and return human-readable text."""
    try:
        import dpkt, socket as _sock, datetime as _dt
        out: list[str] = []
        with open(pcap_path, 'rb') as fh:
            try:
                pcap = dpkt.pcap.Reader(fh)
                fmt  = 'pcap'
            except Exception:
                fh.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(fh)
                    fmt  = 'pcapng'
                except Exception:
                    return '[Unsupported pcap format — cannot parse]'
            out.append(f'Format: {fmt}')
            out.append('-' * 72)
            n = 0
            for ts, buf in pcap:
                n += 1
                if n > 5000:
                    out.append('[truncated after 5000 packets]')
                    break
                ts_s = _dt.datetime.utcfromtimestamp(ts).strftime('%H:%M:%S.%f')
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip  = eth.data
                    if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        def _ntoa(b):
                            return _sock.inet_ntoa(b) if len(b)==4 else str(b)
                        src_ip = _ntoa(ip.src)
                        dst_ip = _ntoa(ip.dst)
                        xl = ip.data
                        if isinstance(xl, dpkt.tcp.TCP):
                            proto, sp, dp = 'TCP', xl.sport, xl.dport
                        elif isinstance(xl, dpkt.udp.UDP):
                            proto, sp, dp = 'UDP', xl.sport, xl.dport
                        elif isinstance(xl, dpkt.icmp.ICMP):
                            proto, sp, dp = 'ICMP', 0, 0
                        else:
                            proto = f'IP/{getattr(ip,"p","?")}'; sp = dp = 0
                        line = (f'#{n:5}  {ts_s}  {proto:<5} '
                                f'{src_ip}:{sp} -> {dst_ip}:{dp}  '
                                f'len={len(buf)}')
                    else:
                        sm = ':'.join(f'{b:02x}' for b in eth.src)
                        dm = ':'.join(f'{b:02x}' for b in eth.dst)
                        line = (f'#{n:5}  {ts_s}  ETH   '
                                f'{sm} -> {dm}  len={len(buf)}')
                except Exception:
                    line = f'#{n:5}  {ts_s}  [parse error]  len={len(buf)}'
                out.append(line)
        return '\n'.join(out) if out else '[empty pcap]'
    except ImportError:
        return ('[dpkt not installed — install with: pip install dpkt\n'
                'Raw bytes cannot be shown without dpkt.]')
    except Exception as e:
        return f'[Error reading pcap: {e}]'

@app.route('/')
def index():
    raw = load_projects()
    projects = {}
    needs_save = False
    for pid, pinfo in raw.get('projects', {}).items():
        # Prefer the cached value already stored in gauntlet_meta.json
        version = str(pinfo.get('device_model_number', '') or '').strip()
        if not version:
            # Lazy migration: read from YAML and cache for future page loads
            yp = pinfo.get('yaml_path', '')
            if yp:
                if not os.path.isabs(yp):
                    yp = os.path.join(_BASE_DIR, yp)
                try:
                    y = load_yaml(yp)
                    version = str(y.get('device_model_number', '') or '').strip()
                    if version:
                        raw['projects'][pid]['device_model_number'] = version
                        needs_save = True
                except Exception:
                    pass
        projects[pid] = {'name': pinfo.get('name', 'Unnamed'), 'id': pid, 'version': version}
    if needs_save:
        try:
            save_projects(raw)
        except Exception:
            pass
        # Auto-import Gearbox projects discovered in the clients directory.
        # project_dir is the authoritative locator for per-project routes
        # (console history / findings / targets) so resolution works even
        # when the discovered project has no top-level YAML.
    _discovered = _discover_gearbox_projects()
    if _discovered:
        _raw = load_projects()
        _changed = False
        for item in _discovered:
            _pid  = str(__import__("uuid").uuid4())
            _meta = item["meta"]
            _cs   = _meta.get("client_short", "project")
            _yaml_path    = item.get("yaml_path", "")
            _project_dir  = item.get("project_dir", "") or item.get("path", "")
            _raw["projects"][_pid] = {
                "id":                _pid,
                "name":              f"{_cs} — discovered (gearbox)",
                "yaml_path":         _yaml_path,
                "project_dir":       _project_dir,
                "created":           _meta.get("created_at", "")[:10],
                "device_model_number": "",
            }
            _changed = True
        if _changed:
            save_projects(_raw)


@app.route('/new_project')
def new_project():
    return render_template(
        'new_project.html',
        interface_types=INTERFACE_TYPES,
        now_year=datetime.now().year,
    )


@app.route('/edit_project/<project_id>')
def edit_project(project_id):
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return redirect(url_for('index'))
    yaml_path = pinfo.get('yaml_path', '')
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    try:
        y = load_yaml(yaml_path)
    except Exception:
        y = {}
    return render_template(
        'edit_project.html',
        project_id=project_id,
        project=y,
        yaml_path=yaml_path,
        interface_types=INTERFACE_TYPES,
        now_year=datetime.now().year,
    )


@app.route('/project/<project_id>')
def project_page(project_id):
    return _render_project(project_id, 'summary')


@app.route('/api/export_json/<project_id>')
def api_export_json(project_id):
    """
    Build and return the structured JSON export for a project.
    The file is also written to the project directory.
    Format: CLIENTSHORT-YEAR-DeviceName-export.json
    """
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    try:
        yaml_data   = load_yaml(pinfo['yaml_path'])
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        export_obj  = _build_export(yaml_data, project_dir)
        # Determine filename
        short  = (yaml_data.get('client_short') or 'PROJ').strip().replace(' ','_').upper()
        year   = str(yaml_data.get('year', datetime.now().year))
        device = (yaml_data.get('device') or 'Device').strip().replace(' ','_').replace('/','-')
        fname  = f'{short}-{year}-{device}-export.json'
        out_path = project_dir / fname
        out_path.write_text(json.dumps(export_obj, indent=2, default=str))
        return jsonify({'ok': True, 'filename': fname,
                        'data': export_obj})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _build_export(yaml_data: dict, project_dir: Path) -> dict:
    """
    Build the full structured export dict from project data.
    """
    # ── Project info (everything from YAML except subdevices) ─────────
    proj_info = {k: v for k, v in yaml_data.items() if k != 'subdevices'}

    # ── Load findings ─────────────────────────────────────────────────
    findings_by_ip_port: dict[tuple, list] = {}
    jsonl_path = project_dir / 'findings.jsonl'
    if jsonl_path.exists():
        for line in jsonl_path.read_text(errors='replace').splitlines():
            if not line.strip(): continue
            try:
                f = json.loads(line)
                key = (f.get('ip',''), str(f.get('port','')))
                findings_by_ip_port.setdefault(key, []).append(f)
            except Exception:
                pass

    # ── Load DB port data ─────────────────────────────────────────────
    db_files   = list(project_dir.rglob('*.db'))
    ports_data: dict[tuple, dict] = {}  # (ip, port) -> port row
    hosts_data: dict[str, list]   = {}  # instance_id -> [ip]
    if db_files:
        try:
            import sqlite3 as _sq
            with _sq.connect(str(db_files[0]), timeout=10) as conn:
                conn.row_factory = _sq.Row
                for row in conn.execute('SELECT * FROM open_ports').fetchall():
                    r = dict(row)
                    iid = f"{r['subdevice']}.{r['interface']}.{r['instance']}"
                    ports_data[(r['ip'], str(r['port']))] = r
                for row in conn.execute('SELECT * FROM discovered_hosts').fetchall():
                    r = dict(row)
                    iid = f"{r['subdevice']}.{r['interface']}.{r['instance']}"
                    hosts_data.setdefault(iid, []).append(r['ip'])
        except Exception:
            pass

    # ── Walk subdevices ───────────────────────────────────────────────
    subdevices_export: dict = {}
    for sd_key, sd in (yaml_data.get('subdevices') or {}).items():
        sd_name = (sd.get('name') if isinstance(sd, dict) else sd_key) or sd_key
        sd_export: dict = {'name': sd_name, 'interfaces': {}}
        ifaces = (sd.get('interfaces') or {}) if isinstance(sd, dict) else {}
        for iface_name, instances in ifaces.items():
            iface_export: dict = {}
            for inst_key, inst_data in (instances.items() if isinstance(instances, dict) else {}):
                iid = f'{sd_key}.{iface_name}.{inst_key}'
                inst_export = _build_instance_export(
                    sd_key, sd_name, iface_name, inst_key, inst_data,
                    project_dir, yaml_data,
                    hosts_data.get(iid, []),
                    ports_data, findings_by_ip_port)
                iface_export[inst_key] = inst_export
            sd_export['interfaces'][iface_name] = iface_export
        subdevices_export[sd_key] = sd_export

    return {
        'project_info':  proj_info,
        'subdevices':    subdevices_export,
        'generated_at':  datetime.now().isoformat(),
    }


def _build_instance_export(
        sd_key, sd_name, iface_name, inst_key, inst_data,
        project_dir, yaml_data,
        host_ips, ports_data, findings_by_ip_port) -> dict:
    """
    Build the export structure for one interface instance per the full spec.
    All file paths are relative to project_dir.parent so the project folder
    name is included and the export is portable.
    """
    import re as _re, fnmatch as _fn

    short  = (yaml_data.get('client_short') or 'proj').strip().replace(' ','_').upper()
    device = (yaml_data.get('device') or 'device').strip().replace(' ','_').replace('/','-')
    sd_dir = (sd_name or sd_key).strip().replace(' ','_')

    # Base for relative paths = parent of the project directory so that
    # all exported paths include the project folder name, e.g.:
    #   ACME-2026-ControlUnit/Ethernet/inst1/NmapPort/192_168_1_1_ports.xml
    rel_base = project_dir.parent

    def _rel(p) -> str:
        """Return path relative to rel_base (project parent), or str(p)."""
        if not p:
            return ''
        try:
            return str(Path(p).resolve().relative_to(rel_base.resolve()))
        except (ValueError, TypeError):
            # Fall back: try relative to project_dir
            try:
                return str(project_dir.name + '/' + str(Path(p).relative_to(project_dir)))
            except Exception:
                return str(p)

    # Locate the instance directory
    candidates = [
        project_dir / short / device / sd_dir / iface_name / inst_key,
        project_dir / short / device / iface_name / inst_key,
        project_dir / f'{short}_{device}_{sd_dir}_{iface_name}_{inst_key}',
        project_dir / f'{short}_{device}_{iface_name}_{inst_key}',
    ]
    inst_dir = next((c for c in candidates if c.exists()), candidates[0])

    export: dict = {
        'location': (inst_data.get('location','') if isinstance(inst_data,dict) else ''),
    }

    # ── Photos ────────────────────────────────────────────────────────────
    photo_dir = inst_dir / 'Photo'
    photos = []
    if photo_dir.exists():
        for ext in ('*.jpg','*.jpeg','*.png','*.webp','*.gif'):
            photos += [_rel(p) for p in sorted(photo_dir.glob(ext))]
    export['photos'] = photos

    if 'ethernet' not in iface_name.lower() and iface_name != 'Ethernet':
        return export

    # ── Subnets with tcpdump/tshark/responder ─────────────────────────────
    subnets: dict = {}
    cd_dir  = inst_dir / 'ConfigDiscovery'
    tc_dir  = inst_dir / 'TrafficCollector'
    resp_dir = inst_dir / 'Responder'
    iface = yaml_data.get('test_interface', 'eth0')

    # Derive subnets from ConfigDiscovery logs
    if cd_dir.exists():
        for txt in sorted(cd_dir.glob('*.txt')):
            try:
                for m in _re.finditer(r'(\d+\.\d+\.\d+\.\d+/\d+)',
                                      txt.read_text(errors='replace')):
                    sn = m.group(1)
                    if sn not in subnets:
                        subnets[sn] = {'subnet': sn}
            except Exception: pass

    # Derive subnets from discovered hosts if none found above
    for ip in host_ips:
        try:
            import ipaddress as _ipa
            net = str(_ipa.ip_network(f'{ip}/24', strict=False))
            if net not in subnets:
                subnets[net] = {'subnet': net}
        except Exception: pass

    # Attach tcpdump / tshark / responder to each subnet
    for sn_key, sn_data in subnets.items():
        # ── tcpdump ──────────────────────────────────────────────────────
        tcpdump_files = sorted(tc_dir.glob('*.pcap')) if tc_dir.exists() else []
        tcpdump_cmd   = f'tcpdump -i {iface} -w <output.pcap> -G <seconds> -W 1'
        obs_ips: list = []
        if tc_dir.exists():
            for tf in tc_dir.glob('*.txt'):
                try:
                    for m in _re.finditer(
                            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
                            tf.read_text(errors='replace')):
                        v = m.group(1)
                        if v not in obs_ips:
                            obs_ips.append(v)
                except Exception: pass
        sn_data['tcpdump'] = {
            'command':      tcpdump_cmd,
            'output_files': [_rel(f) for f in tcpdump_files],
            'observed_ips': obs_ips,
        } if tc_dir.exists() else {}

        # ── tshark ───────────────────────────────────────────────────────
        tshark_files = sorted(tc_dir.glob('*tshark*')) if tc_dir.exists() else []
        tshark_cmd   = (f'tshark -r <capture.pcap> -T fields '
                        f'-e ip.src -e ip.dst -e _ws.col.Protocol')
        sn_data['tshark'] = {
            'command':      tshark_cmd,
            'output_files': [_rel(f) for f in tshark_files],
            'observed_ips': [],
        } if tshark_files else {}

        # ── responder ────────────────────────────────────────────────────
        resp_logs  = sorted(resp_dir.glob('*.log')) if resp_dir.exists() else []
        resp_creds = (sorted(resp_dir.glob('*credentials*')) +
                      sorted(resp_dir.glob('*hashes*'))) if resp_dir.exists() else []
        resp_cmd   = f'responder -I {iface} -F -P'
        dom_users: list = []
        if resp_dir.exists():
            for lf in resp_logs:
                try:
                    content = lf.read_text(errors='replace')
                    for m in _re.finditer(
                            r'(?:DOMAIN|User)\s*:\s*(\S+)', content, _re.I):
                        v = m.group(1).strip()
                        if v and v not in dom_users:
                            dom_users.append(v)
                except Exception: pass
        sn_data['responder'] = {
            'interface':             iface,
            'command':               resp_cmd,
            'output_files':          [_rel(f) for f in resp_logs + resp_creds],
            'observed_ips':          [],
            'observed_domain_users': dom_users,
        } if resp_dir.exists() else {}

    export['subnets'] = subnets

    # ── Tool-command lookup helpers ───────────────────────────────────────
    # Map tool name → canonical command template for use in validation_tools
    def _tool_cmd(tool: str, ip: str, port: str, url: str = '') -> str:
        t = tool.lower()
        if t == 'nmap':
            return f'nmap -sV --open -p {port} {ip}'
        if t == 'nessus':
            return f'nessus (API scan targeting {ip})'
        if t in ('nuclei','nuclei-http'):
            return (f'nuclei -u {url or f"http://{ip}:{port}"} '
                    f'-severity critical,high,medium,low,info -silent -no-color')
        if t in ('sslscan','ssl-scan'):
            return f'sslscan --no-colour {ip}:{port}'
        if t in ('testssl','testssl.sh'):
            return f'testssl.sh {ip}:{port}'
        if t in ('shcheck','sh-check'):
            return f'shcheck.py -d {url or f"https://{ip}:{port}"}'
        if t in ('ssh-audit','ssh_audit'):
            return f'ssh-audit -p {port} {ip}'
        if t in ('nmap-ssh',):
            return (f'nmap -p {port} '
                    f'--script ssh-auth-methods,ssh2-enum-algos,sshv1 {ip}')
        if t in ('nmap-smb','smbmap'):
            return f'smbmap -H {ip} -P {port} -u anonymous --no-pass'
        if t in ('nmap-ftp',):
            return (f'nmap -p {port} '
                    f'--script ftp-anon,ftp-bounce,ftp-syst,banner {ip}')
        if t in ('openssl',):
            return (f'openssl s_client -connect {ip}:{port} '
                    f'-showcerts </dev/null')
        if t in ('curl',):
            return f'curl -sSk -I {url or f"http://{ip}:{port}/"}'
        if t in ('banner_grab','bannergrab'):
            return f'(socket connect {ip}:{port})'
        if t in ('gowitness',):
            return (f'gowitness scan single --url '
                    f'{url or f"http://{ip}:{port}"}')
        if t in ('wget',):
            return (f'wget --mirror --no-check-certificate --no-parent '
                    f'--convert-links --level=10 '
                    f'{url or f"http://{ip}:{port}"}')
        if t in ('responder',):
            return f'responder -I {iface} -F -P'
        return tool

    # ── Live IPs ──────────────────────────────────────────────────────────
    live_ips: dict = {}
    for ip in host_ips:
        ip_safe = ip.replace('.', '_')

        nmap_live_dir   = inst_dir / 'NmapLive'
        nmap_live_files = sorted(nmap_live_dir.glob(f'*{ip_safe}*')) \
                          if nmap_live_dir.exists() else []
        discover_tool   = 'nmap' if nmap_live_files else 'tcpdump'
        discover_cmd    = (f'nmap -sn {ip}' if nmap_live_files
                           else 'tcpdump (passive ARP observation)')
        discover_file   = _rel(nmap_live_files[0]) if nmap_live_files else ''

        ip_ports: dict = {}
        for (p_ip, p_port), p_data in ports_data.items():
            if p_ip != ip:
                continue
            port_safe = f'{ip_safe}_{p_port}'
            svc   = p_data.get('service', '')
            ver   = p_data.get('version', '')
            proto = p_data.get('protocol', 'tcp')

            # Nmap output file for this port
            nmap_port_dir   = inst_dir / 'NmapPort'
            nmap_port_files = []
            if nmap_port_dir.exists():
                for f in nmap_port_dir.glob(f'*{ip_safe}*'):
                    if f.is_file():
                        nmap_port_files.append(_rel(f))
            nmap_port_cmd = (f'nmap -sV --open '
                             f'--max-rtt-timeout 500ms -p- {ip}')

            # ── URLs (web ports only) ──────────────────────────────────────
            http_svcs = {'http','http-alt','https','https-alt','ssl','tls','www'}
            is_web    = (svc.lower() in http_svcs or int(p_port) in {
                80,443,8080,8443,8000,8008,8081,8082,8880,3000,5000,9080,
                4443,9443,10443})
            urls_export: list = []

            if is_web:
                scheme = ('https' if (svc.lower() in {'https','https-alt','ssl','tls'}
                                      or int(p_port) in {443,8443,4443,9443,10443})
                          else 'http')
                url = f'{scheme}://{ip}:{p_port}'

                # Screenshots
                ss_dir = inst_dir / 'Web' / 'screenshots'
                screenshots_list = []
                seen_ss: set = set()
                if ss_dir.exists():
                    for ss in sorted(ss_dir.rglob('*')):
                        if not ss.is_file(): continue
                        if str(ss) in seen_ss: continue
                        if port_safe in ss.name or ip_safe in ss.name:
                            seen_ss.add(str(ss))
                            screenshots_list.append({
                                'tool':    'gowitness',
                                'command': (f'gowitness scan single '
                                            f'--url {url} '
                                            f'--screenshot-path <screenshots_dir>'),
                                'file':    _rel(ss),
                            })

                # Scrapes
                spider_root  = inst_dir / 'Web' / 'spider'
                scrapes_list = []
                if spider_root.exists():
                    for sf in sorted(spider_root.rglob('*')):
                        if not sf.is_file(): continue
                        try:
                            rel_sf  = str(sf.relative_to(spider_root))
                            src_url = f'{url}/{rel_sf}'.replace('\\','/')
                        except Exception:
                            src_url = url
                        scrapes_list.append({
                            'tool':       'wget',
                            'depth':      10,
                            'command':    (f'wget --mirror '
                                          f'--no-check-certificate '
                                          f'--no-parent --convert-links '
                                          f'--level=10 {url}'),
                            'file':       _rel(sf),
                            'source_url': src_url,
                        })

                # Certificates
                ssl_dir   = inst_dir / 'SSL'
                certs_list = []
                if ssl_dir.exists():
                    for cf in ssl_dir.glob(f'*{port_safe}*info*'):
                        if cf.is_file():
                            certs_list.append({
                                'tool':    'openssl',
                                'command': (f'openssl s_client '
                                            f'-connect {ip}:{p_port} '
                                            f'-showcerts </dev/null'),
                                'file':    _rel(cf),
                            })

                urls_export.append({
                    'url':          url,
                    'screenshots':  screenshots_list,
                    'scrapes':      scrapes_list[:200],
                    'certificates': certs_list,
                })

            # ── Findings ──────────────────────────────────────────────────
            port_findings  = findings_by_ip_port.get((ip, p_port), [])
            findings_export = []
            TOOL_PRIO = {'nessus':0,'nmap':1,'nuclei':2}

            for fnd in port_findings:
                tools_used = fnd.get('tools_used', [])
                if isinstance(tools_used, str):
                    try:    tools_used = json.loads(tools_used)
                    except Exception: tools_used = [tools_used]
                sorted_tools  = sorted(tools_used,
                                       key=lambda t: TOOL_PRIO.get(t.lower(), 3))
                primary_tool  = sorted_tools[0] if sorted_tools else ''
                secondary     = sorted_tools[1:]

                # commands_used list from finding — try to align by position
                cmds_used = fnd.get('commands_used') or []
                if isinstance(cmds_used, str):
                    try:    cmds_used = json.loads(cmds_used)
                    except Exception: cmds_used = [cmds_used]

                def _cmd_for(tool: str, idx: int) -> str:
                    """Return stored command if available, else construct one."""
                    if idx < len(cmds_used) and cmds_used[idx]:
                        return cmds_used[idx]
                    u = (urls_export[0]['url']
                         if urls_export else f'http://{ip}:{p_port}')
                    return _tool_cmd(tool, ip, p_port, u)

                def _file_for(tool: str) -> str:
                    """Best-effort output file for a tool/port combination."""
                    for mname in ('NmapPort','SSH','SSL','SMB','FTP',
                                  'Nuclei','BannerGrab','Nessus','Web'):
                        mdir = inst_dir / mname
                        if not mdir.exists(): continue
                        for f in mdir.glob(f'*{port_safe}*'):
                            if tool.lower().replace('-','') in \
                                    f.name.lower().replace('-',''):
                                return _rel(f)
                    # Fall back to finding's own output_file
                    return _rel(fnd.get('output_file', ''))

                findings_export.append({
                    'title':       fnd.get('title', ''),
                    'risk':        fnd.get('risk', ''),
                    'cves':        fnd.get('cve_ids', []),
                    'description': fnd.get('description', ''),
                    'affected':    fnd.get('affected', []),
                    'primary_tool': {
                        'tool':        primary_tool,
                        'command':     _cmd_for(primary_tool, 0),
                        'output_file': _rel(fnd.get('output_file', '')),
                    },
                    'validation_tools': [
                        {
                            'tool':        t,
                            'command':     _cmd_for(t, i + 1),
                            'output_file': _file_for(t),
                        }
                        for i, t in enumerate(secondary)
                    ],
                })

            ip_ports[p_port] = {
                'port':        int(p_port),
                'port_type':   proto,
                'service':     svc,
                'software':    svc,
                'version':     ver,
                'tool':        'nmap',
                'command':     nmap_port_cmd,
                'output_file': nmap_port_files[0] if nmap_port_files else '',
                'urls':        urls_export,
                'findings':    findings_export,
            }

        live_ips[ip] = {
            'ip':          ip,
            'tool':        discover_tool,
            'command':     discover_cmd,
            'output_file': discover_file,
            'ports':       ip_ports,
        }

    export['live_ips'] = live_ips
    return export

@app.route('/project/<project_id>/<tab>')
def project_tab(project_id, tab):
    return _render_project(project_id, tab)


def _render_project(project_id: str, tab: str):
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return redirect(url_for('index'))
    # Ensure id is present (may be missing on older records)
    pinfo = dict(pinfo, id=project_id)
    enriched = enrich_project(pinfo)
    if not enriched:
        return redirect(url_for('index'))
    valid_tabs = ['summary', 'testing', 'findings', 'targets', 'evidence',
                  'logs', 'gearbox_logs', 'gauntlet_logs', 'observations',
                  'errors', 'deleted']
    # Redirect legacy tab names to combined logs tab
    if tab in ('gearbox_logs', 'gauntlet_logs'):
        tab = 'logs' 
    if tab not in valid_tabs:
        tab = 'summary'
    pm = enriched['progress_map']
    total_instances     = len(pm)
    completed_instances = sum(1 for i in pm.values() if i.get('completed'))
    _sys_info = {}
    try:
        try:
            from importlib.util import spec_from_file_location, module_from_spec
            _spec = spec_from_file_location(
                "pr0t31n_system_info",
                os.path.join(os.path.dirname(__file__), "pr0t31n_system_info.py"),
            )
            _si = module_from_spec(_spec)
            _spec.loader.exec_module(_si)
        except Exception:
            import sys as _s
            if "/opt/pr0t31n/shared" not in _s.path:
                _s.path.insert(0, "/opt/pr0t31n/shared")
            import pr0t31n_system_info as _si
        _sys_info = _si.collect()
    except Exception:
        pass
    return render_template(
        'project.html',
        project=enriched['yaml'],
        project_id=project_id,
        active_tab=tab,
        total_modules=enriched['total_modules'],
        completed_modules=enriched['completed_modules'],
        total_instances=total_instances,
        completed_instances=completed_instances,
        module_status=enriched.get('progress', {}).get('module_status', {}),
        progress_map=enriched['progress_map'],
        findings=[],
        findings_count=enriched.get('findings_count', 0),
        findings_risk_counts=enriched.get('findings_risk_counts', {}),
        targets_count=enriched.get('targets_count', 0),
        interface_modules=INTERFACE_MODULES,
        module_evidence=MODULE_EVIDENCE,
        module_tools=MODULE_TOOLS,
        risk_colors=RISK_COLORS,
        risk_levels=RISK_LEVELS,
        classifications=CLASSIFICATIONS,
        yaml_path=pinfo.get('yaml_path', ''),
        integrity_resets=enriched.get('integrity_resets', []),
        device_tool_photos=enriched.get('device_tool_photos', []),
        subdevice_photos_by_sd=enriched.get('subdevice_photos_by_sd', {}),
        system_info=_sys_info,
    )


# ─── API: System Info ─────────────────────────────────────────────────────────

@app.route("/api/system_info")
def api_system_info():
    """Return testing host/device information."""
    try:
        try:
            from importlib.util import spec_from_file_location, module_from_spec
            _spec = spec_from_file_location(
                "pr0t31n_system_info",
                os.path.join(os.path.dirname(__file__), "pr0t31n_system_info.py"),
            )
            _si = module_from_spec(_spec)
            _spec.loader.exec_module(_si)
        except Exception:
            import sys as _s
            if "/opt/pr0t31n/shared" not in _s.path:
                _s.path.insert(0, "/opt/pr0t31n/shared")
            import pr0t31n_system_info as _si
        return jsonify(_si.collect())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─── API: System Cleanup ───────────────────────────────────────────────────────

@app.route('/api/system_cleanup', methods=['POST'])
def api_system_cleanup():
    """
    Run the system cleanup script (cleanup.py):
      • Kill any running Responder instance
      • Stop any running Nessus scans
      • Revert the test_direct interface to DHCP default
    Returns a JSON result dict from cleanup.run_cleanup().
    """
    try:
        _spec = _imputil.spec_from_file_location(
            "cleanup",
            os.path.join(_BASE_DIR, "cleanup.py"))
        _mod = _imputil.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        results = _mod.run_cleanup()
    except Exception as e:
        return jsonify({"overall_status": "error", "error": str(e)}), 500
    return jsonify(results)


# ─── API: Migrate instance keys ────────────────────────────────────────────────

@app.route('/api/migrate_keys/<project_id>', methods=['POST'])
def api_migrate_keys(project_id):
    """
    Explicitly migrate auto-generated instance/subdevice YAML keys to user-defined names.
    Safe to call multiple times — a no-op if keys are already clean.
    """
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    _, changes = migrate_yaml_instance_keys(pinfo.get('yaml_path', ''))
    return jsonify({'changes': changes, 'count': len(changes)})


# ─── API: Project Detail (AJAX on home page) ───────────────────────────────────

@app.route('/api/project/<project_id>')
def api_project_detail(project_id):
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Not found'}), 404
    pinfo = dict(pinfo, id=project_id)
    enriched = enrich_project(pinfo)
    if not enriched:
        return jsonify({'error': 'Could not load project YAML'}), 500
    # Remove large findings list for the summary card (just count)
    enriched_copy = {k: v for k, v in enriched.items() if k != 'findings'}
    enriched_copy['findings_count'] = enriched.get('findings_count', 0)
    # Instance-level completion counts (progress_map already present in enriched_copy)
    pm = enriched.get('progress_map', {})
    enriched_copy['total_instances']     = len(pm)
    enriched_copy['completed_instances_count'] = sum(
        1 for inst in pm.values() if inst.get('completed'))
    return jsonify(enriched_copy)


# ─── API: Create Project ────────────────────────────────────────────────────────

@app.route('/api/create_project', methods=['POST'])
def create_project():
    data: dict = request.get_json(force=True) or {}

    target_dir = (data.get('target_dir') or '').strip()
    _cs_raw  = (data.get('client_short') or '').strip()
    _sd_raw  = (data.get('start_date')   or '').strip()

    if target_dir:
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception as e:
            return jsonify({'error': f'Cannot create directory: {e}'}), 400
    elif _cs_raw:
        # Auto-build structured directory from client_short + start_date
        _structured = _build_project_dir_structured(_cs_raw, _sd_raw)
        target_dir  = str(_structured)
    else:
        return jsonify({'error': 'Target directory or client_short is required'}), 400

    yaml_data = _build_yaml(data)

    client_short = (data.get('client_short') or 'project').strip().replace(' ', '_').upper()
    device       = (data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')
    yaml_filename = f"{client_short}_{device}.yaml"
    yaml_path     = os.path.join(target_dir, yaml_filename)

    with open(yaml_path, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    projects_data = load_projects()
    project_id    = str(uuid.uuid4())
    project_name  = f"{data.get('client_name', 'Client')} — {data.get('device', 'Device')}"
    projects_data['projects'][project_id] = {
        'id':                      project_id,
        'name':                    project_name,
        'yaml_path':               yaml_path,
        'created':                 datetime.now().strftime('%Y-%m-%d'),
        'device_model_number': str(data.get('device_model', '') or '').strip(),
    }
    save_projects(projects_data)

    return jsonify({'success': True, 'project_id': project_id})


@app.route('/api/update_project/<project_id>', methods=['POST'])
def update_project(project_id):
    data: dict = request.get_json(force=True) or {}

    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    yaml_path = pinfo.get('yaml_path', '')
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)

    if not os.path.isfile(yaml_path):
        return jsonify({'error': f'YAML file not found: {yaml_path}'}), 400

    yaml_data = _build_yaml(data)

    # Check if client_short or device name changed — if so rename the YAML file
    client_short = (data.get('client_short') or 'project').strip().replace(' ', '_').upper()
    device       = (data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')
    new_filename  = f"{client_short}_{device}.yaml"
    project_dir   = os.path.dirname(yaml_path)
    new_yaml_path = os.path.join(project_dir, new_filename)

    # Write updated YAML (to new path if renamed, old path otherwise)
    try:
        with open(new_yaml_path, 'w') as f:
            yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception as e:
        return jsonify({'error': f'Failed to write YAML: {e}'}), 500

    # Remove old YAML if it was renamed
    if new_yaml_path != yaml_path and os.path.isfile(yaml_path):
        try:
            os.remove(yaml_path)
        except Exception:
            pass

    # Update project metadata
    project_name = f"{data.get('client_name', 'Client')} — {data.get('device', 'Device')}"
    raw['projects'][project_id]['name']                = project_name
    raw['projects'][project_id]['yaml_path']           = new_yaml_path
    raw['projects'][project_id]['device_model_number'] = str(data.get('device_model', '') or '').strip()
    save_projects(raw)

    # Invalidate the project dir cache entry so subsequent requests re-resolve
    _project_dir_cache.pop(project_id, None)

    # Clean up progress.json: remove module_status entries and completed_instances
    # for any instances that no longer exist in the updated YAML.  This prevents
    # removed interfaces from continuing to appear as outstanding work.
    try:
        progress_file = os.path.join(os.path.dirname(os.path.abspath(new_yaml_path)), 'progress.json')
        if os.path.isfile(progress_file):
            with open(progress_file, 'r', encoding='utf-8') as _pf:
                _prog = json.load(_pf)
            _live_iids = {
                inst['instance_id']
                for inst in collect_all_instances(yaml_data)
            }
            _ms = _prog.get('module_status', {})
            # Remove module_status keys whose instance prefix is no longer in scope
            stale_keys = [
                k for k in list(_ms.keys())
                if '.'.join(k.split('.')[:3]) not in _live_iids
            ]
            for k in stale_keys:
                del _ms[k]
            # Remove stale instance IDs from completed_instances
            _prog['completed_instances'] = [
                iid for iid in _prog.get('completed_instances', [])
                if iid in _live_iids
            ]
            with open(progress_file, 'w', encoding='utf-8') as _pf:
                json.dump(_prog, _pf, indent=2)
    except Exception:
        pass  # Progress cleanup is best-effort; don't block the save response

    return jsonify({'success': True, 'project_id': project_id})


def _build_yaml(data: dict) -> dict:
    yaml_out = {
        'client_name':             data.get('client_name', ''),
        'client_short':            data.get('client_short', ''),
        'consultant': {
            'name':  data.get('consultant_name', ''),
            'title': data.get('consultant_title', ''),
            'email': data.get('consultant_email', ''),
        },
        'client_poc': {
            'name':  data.get('poc_name', ''),
            'phone': data.get('poc_phone', ''),
            'email': data.get('poc_email', ''),
        },
        'year':                    int(data.get('year', datetime.now().year)),
        'device':                  data.get('device', ''),
        'device_model_number':     data.get('device_model', ''),
        'device_software_version': data.get('device_sw_version', ''),
        'version':                 data.get('version', '1.0'),
        'start_date':              data.get('start_date', ''),
        'end_date':                data.get('end_date', ''),
        'subdevices':              {},
    }

    for i, sd in enumerate(data.get('subdevices') or []):
        sd_name  = (sd.get('name') or f'subdevice_{i + 1}').strip()
        # Use a sanitised version of the name as the YAML key
        sd_key   = re.sub(r'[^\w]', '_', sd_name).lower() or f'subdevice_{i + 1}'
        sd_entry = {
            'name':       sd_name,
            'interfaces': {},
        }
        for iface, instances in (sd.get('interfaces') or {}).items():
            if iface not in INTERFACE_MODULES:
                continue   # only accept known interface types
            if not instances:
                continue   # skip interfaces with no instances — avoids ghost instances
            sd_entry['interfaces'][iface] = {}
            for j, inst in enumerate(instances or []):
                # Prefer the user-supplied instance name; fall back to inst_N
                inst_name = (inst.get('name') or inst.get('location') or '').strip()
                inst_key  = (re.sub(r'[^\w]', '_', inst_name).lower()
                             if inst_name else f'inst_{j + 1}')
                sd_entry['interfaces'][iface][inst_key] = {
                    'location': inst.get('location', '')
                }
        yaml_out['subdevices'][sd_key] = sd_entry

    return yaml_out


# ─── API: Photo Upload ──────────────────────────────────────────────────────────

@app.route('/join/<project_id>')
def join_page(project_id):
    """Mobile-optimised companion page for joining a live project session."""
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return redirect(url_for('index'))
    try:
        yaml_data = load_yaml(pinfo['yaml_path'])
    except Exception:
        yaml_data = {}
    local_ip   = get_local_ip()
    flask_port = app.config.get('SERVER_PORT', 5000)
    join_url   = f'https://{local_ip}:{flask_port}/join/{project_id}'
    return render_template(
        'join.html',
        project_id=project_id,
        project=yaml_data,
        interface_modules=INTERFACE_MODULES,
        join_url=join_url,
    )


@app.route('/api/join_qr_img/<project_id>')
def join_qr_img(project_id):
    """
    Return a QR code image for the join URL.
    Optional query param: ?ip=192.168.x.x  — generate QR for that specific IP.
    Tries in order:
      1. qrcode + Pillow → PNG
      2. qrcode → SVG fallback
      3. api.qrserver.com proxy (requires internet)
      4. Minimal SVG placeholder with URL text
    """
    import io as _io

    flask_port = app.config.get('SERVER_PORT', 5000)
    ip_override = request.args.get('ip', '').strip()
    host = ip_override if ip_override else get_local_ip()
    url  = f'https://{host}:{flask_port}/join/{project_id}'

    # 1. qrcode + Pillow → PNG (convert to L/greyscale for broad browser compat)
    try:
        import qrcode as _qrcode
        buf = _io.BytesIO()
        img = _qrcode.make(url, box_size=5, border=3)
        # qrcode returns a mode-1 (bilevel) image; L mode renders in all browsers
        img.convert('L').save(buf, format='PNG')
        return Response(buf.getvalue(), mimetype='image/png')
    except Exception:
        pass

    # 2. qrcode → SVG (no Pillow needed)
    try:
        import qrcode as _qrcode
        import qrcode.image.svg as _svg
        buf = _io.BytesIO()
        _qrcode.make(url, image_factory=_svg.SvgImage, box_size=4, border=2).save(buf)
        return Response(buf.getvalue(), mimetype='image/svg+xml')
    except Exception:
        pass

    # 3. Proxy to api.qrserver.com
    try:
        import urllib.request as _ureq, urllib.parse as _uparse
        qr_url = ('https://api.qrserver.com/v1/create-qr-code/?'
                  + _uparse.urlencode({'size': '160x160', 'data': url,
                                       'margin': '2', 'format': 'png'}))
        with _ureq.urlopen(qr_url, timeout=5) as resp:
            return Response(resp.read(), mimetype='image/png')
    except Exception:
        pass

    # 4. SVG placeholder — shows the URL so it can be typed manually
    escaped = url.replace('&', '&amp;').replace('<', '&lt;')
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="80">'
        '<rect width="200" height="80" fill="white"/>'
        '<text x="100" y="22" font-size="9" text-anchor="middle" fill="#333">'
        'QR unavailable — visit:</text>'
        f'<text x="100" y="40" font-size="7" text-anchor="middle" fill="#c00">'
        f'{escaped}</text>'
        '</svg>'
    )
    return Response(svg, mimetype='image/svg+xml')


@app.route('/api/join_interfaces/<project_id>')
def join_interfaces(project_id):
    """
    Return all network interfaces as a JSON list so the client can render
    a per-interface QR-code picker.
    Each entry: {name, ip, url}
    """
    flask_port = app.config.get('SERVER_PORT', 5000)
    ifaces = get_all_interfaces()
    entries = [
        {
            'name': iface['name'],
            'ip':   iface['ip'],
            'url':  f"https://{iface['ip']}:{flask_port}/join/{project_id}",
            'qr':   f"/api/join_qr_img/{project_id}?ip={iface['ip']}",
        }
        for iface in ifaces
    ]
    return jsonify({'interfaces': entries, 'project_id': project_id})


@app.route('/api/join_qr/<project_id>')
def join_qr(project_id):
    """Return the primary join URL as JSON for backward compat."""
    local_ip   = get_local_ip()
    flask_port = app.config.get('SERVER_PORT', 5000)
    url        = f'https://{local_ip}:{flask_port}/join/{project_id}'
    return jsonify({'url': url, 'project_id': project_id})



@app.route('/api/upload_photo', methods=['POST'])
def upload_photo():
    """Receive a photo upload from mobile device during testing."""
    project_id  = request.form.get('project_id', '').strip()
    instance_id = request.form.get('instance_id', '').strip()

    if 'photo' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    photo = request.files['photo']

    # Determine extension — iOS live captures report an empty filename,
    # so fall back to the content-type header
    filename = photo.filename or ''
    ext = ''
    if '.' in filename:
        ext = filename.rsplit('.', 1)[-1].lower()
    if not ext:
        ct  = (photo.content_type or '').lower()
        ext = {'image/jpeg': 'jpg', 'image/png': 'png',
               'image/gif': 'gif', 'image/webp': 'webp'}.get(ct, 'jpg')
    if ext not in {'jpg', 'jpeg', 'png', 'gif', 'webp'}:
        ext = 'jpg'


    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        # Fallback: whitespace/case-tolerant match for mobile browsers that
        # inject stray characters into FormData values
        pid_clean = project_id.strip().lower()
        for k, v in raw.get('projects', {}).items():
            if k.strip().lower() == pid_clean:
                pinfo      = v
                project_id = k
                break
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    yaml_path   = pinfo.get('yaml_path', '')
    project_dir = os.path.dirname(os.path.abspath(yaml_path))
    parts       = (instance_id or '').split('.')

    # Fall back to stored photo context if instance_id is missing or invalid
    if len(parts) != 3 and project_id in _photo_context:
        ctx         = _photo_context[project_id]
        instance_id = ctx.get('instance_id', '')
        parts       = instance_id.split('.')

    try:
        yaml_data   = load_yaml(yaml_path)
        short  = (yaml_data.get('client_short') or 'proj').strip().replace(' ', '_').upper()
        device = (yaml_data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')

        if len(parts) == 3:
            sd_key, interface, inst_key = parts

            # ── Virtual interface: device-level tool photos ────────────────────
            if sd_key == '_device_' and interface == 'Tools':
                photo_dir   = Path(project_dir) / short / device / '_Tools' / inst_key / 'Photo'
                file_prefix = f'{short}_{device}_tools_{inst_key}'

            # ── Virtual interface: subdevice-level photos ──────────────────────
            elif interface == '_photos_':
                sd_name = ''
                for virt in collect_subdevice_photos(yaml_data):
                    if virt['sd_key'] == sd_key:
                        sd_name = virt['sd_name']
                        break
                sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-') if sd_name else sd_key
                photo_dir   = Path(project_dir) / short / device / sd_dir / '_Photos' / inst_key / 'Photo'
                file_prefix = f'{short}_{device}_{sd_dir}_photos_{inst_key}'

            # ── Normal interface ───────────────────────────────────────────────
            else:
                subdevices = yaml_data.get('subdevices') or {}
                if isinstance(subdevices, dict):
                    sd_entry = subdevices.get(sd_key, {})
                    sd_name  = (sd_entry.get('name') if isinstance(sd_entry, dict) else sd_key) or sd_key
                elif isinstance(subdevices, list):
                    sd_name = sd_key
                    for sd in subdevices:
                        if isinstance(sd, dict) and sd.get('name', '').lower().replace(' ', '_') == sd_key:
                            sd_name = sd.get('name', sd_key)
                            break
                else:
                    sd_name = sd_key
                sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-')
                if sd_dir:
                    photo_dir   = Path(project_dir) / short / device / sd_dir / interface / inst_key / 'Photo'
                    file_prefix = f"{short}_{device}_{sd_dir}_{interface}_{inst_key}"
                else:
                    photo_dir   = Path(project_dir) / short / device / interface / inst_key / 'Photo'
                    file_prefix = f"{short}_{device}_{interface}_{inst_key}"
        else:
            photo_dir   = Path(project_dir) / '_unassigned_photos'
            file_prefix = f"{short}_{device}_unassigned"

        photo_dir.mkdir(parents=True, exist_ok=True)

        # Incremental naming: keep all photos, never overwrite
        import re as _re
        existing_indices = []
        for f in photo_dir.iterdir():
            if not f.is_file():
                continue
            m = _re.match(
                rf'^{_re.escape(file_prefix)}_photo(?:_(\d+))?\.({ext})$',
                f.name, _re.IGNORECASE)
            if m:
                existing_indices.append(int(m.group(1)) if m.group(1) else 0)

        save_name = (f"{file_prefix}_photo_{max(existing_indices)+1}.{ext}"
                     if existing_indices else f"{file_prefix}_photo.{ext}")
        save_path = str(photo_dir / save_name)
        photo.save(save_path)

        socketio.emit('photo_uploaded', {
            'instance_id': instance_id,
            'filename':    save_name,
            'path':        save_path,
        }, room=_room(project_id))

        # Mark the photo module complete in progress.json
        if len(parts) == 3:
            _ctx    = _photo_context.get(project_id, {})
            _module = _ctx.get('module') or 'Photo'
            _mark_photo_module_complete(
                yaml_path, project_id, sd_key, interface, inst_key, _module)

        # Unblock the gearbox prompt queue if a photo prompt is waiting.
        # Also resolve the pending prompt so all sessions dismiss their UI —
        # the join page must NOT emit gearbox_answer after upload_photo succeeds
        # because that would double-queue the answer and auto-answer the next prompt.
        q = _answer_queues.get(project_id)
        if q:
            q.put(save_path)
            _pending_prompts.pop(project_id, None)
            socketio.emit('prompt_resolved', {}, room=_room(project_id))

        return jsonify({'success': True, 'path': save_path})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── API: Live Logs & Observations ────────────────────────────────────────────


def _scan_log_files_from_dir(project_id: str) -> list:
    """Scan project directory for any .log files and return them as log entries."""
    pdir = _project_dir_for(project_id)
    if not pdir:
        return []
    entries: list = []
    try:
        from pathlib import Path as _P
        for log_file in sorted(_P(pdir).rglob('*.log')):
            if log_file.stat().st_size == 0:
                continue
            try:
                lines = log_file.read_text(encoding='utf-8', errors='replace').splitlines()
                for line in lines[-500:]:   # last 500 lines per file
                    line = line.strip()
                    if not line:
                        continue
                    # Detect level from content
                    level = 'INFO'
                    lower = line.lower()
                    if 'error' in lower or 'fail' in lower or 'exception' in lower:
                        level = 'ERROR'
                    elif 'warn' in lower:
                        level = 'WARNING'
                    entries.append({
                        'ts':      '',
                        'level':   level,
                        'message': f"[{log_file.name}] {line}",
                        'tool':    log_file.stem,
                    })
            except Exception:
                pass
    except Exception:
        pass
    return entries[-2000:]   # cap total

@app.route('/api/gearbox_log/<project_id>')
def api_gearbox_log(project_id):
    entries = _gearbox_log.get(project_id, [])
    if not entries:
        entries = _load_log_from_disk(project_id, 'gearbox_log.jsonl')
    if not entries:
        # Last resort: scan for any .log files in project dir produced by gearbox
        entries = _scan_log_files_from_dir(project_id)
    return jsonify({'entries': entries})

@app.route('/api/combined_logs/<project_id>')
def api_combined_logs(project_id):
    """Return merged gearbox + gauntlet log entries sorted by timestamp."""
    gb   = _gearbox_log.get(project_id, [])
    gal  = _gauntlet_log.get(project_id, [])
    # Tag each entry with its source
    tagged = ([dict(e, source_log='gearbox') for e in gb] +
              [dict(e, source_log='gauntlet') for e in gal])
    tagged.sort(key=lambda e: e.get('ts', ''))
    return jsonify({'entries': tagged})

@app.route('/api/gauntlet_log/<project_id>')
def api_gauntlet_log(project_id):
    entries = _gauntlet_log.get(project_id, [])
    if not entries:
        entries = _load_log_from_disk(project_id, 'gauntlet_log.jsonl')
    return jsonify({'entries': entries})


def _synthesise_observations_from_findings(project_id: str) -> list:
    """Build synthetic observations from findings.jsonl for completed projects."""
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return []
    try:
        findings = load_findings(pinfo.get('yaml_path', ''))
        seen: set = set()
        obs: list = []
        for f in findings:
            key = f"{f.get('interface','')}.{f.get('instance','')}.{f.get('ip','')}."                   f"{','.join(f.get('tools_used') or [])}"
            if key in seen:
                continue
            seen.add(key)
            tools = ', '.join(f.get('tools_used') or [f.get('tool', '')])
            obs.append({
                'ts':          f.get('timestamp', ''),
                'title':       f"Finding — {f.get('title', '')[:60]}",
                'description': f"{f.get('risk', '')} finding by {tools} on "
                               f"{f.get('ip', '') or 'unknown'}"
                               f"{':%s' % f.get('port') if f.get('port') else ''}",
                'tool':        tools,
                'risk':        f.get('risk', 'Informational'),
                'output_file': f.get('output_file', ''),
                'synthesised': True,
            })
        return obs[:500]   # cap to avoid huge responses
    except Exception:
        return []

@app.route('/api/observations/<project_id>')
def api_observations(project_id):
    entries = _observations.get(project_id, [])
    if not entries:
        entries = _load_log_from_disk(project_id, 'observations.jsonl')
    if not entries:
        # Synthesise lightweight observations from findings.jsonl so the tab
        # is never completely empty for a completed project.
        entries = _synthesise_observations_from_findings(project_id)
    return jsonify({'entries': entries})

def _load_console_history_from_disk(project_id: str, limit: int = 2000) -> list:
    """Reconstruct console-history entries for a discovered/closed project.

    The live in-memory _console_buffer is only populated by Gauntlet's
    Popen-capture pipeline during an active scan.  For discovered projects
    (or projects whose Gauntlet process restarted), this returns an
    approximate transcript reconstructed from on-disk artifacts in order
    of preference:

      1. <project_dir>/console_history.jsonl  (future Gauntlet may persist)
      2. <project_dir>/scan.log               (Gearbox writes per Section 13)
      3. <project_dir>/gearbox_log.jsonl      (Gauntlet's own structured log)
      4. <project_dir>/*.log                  (last-resort scan of sibling logs)

    Output shape matches the live buffer: [{text, stream, ts}, ...].
    Returns at most *limit* entries (most-recent wins).
    """
    pdir = _project_dir_for(project_id)
    if not pdir:
        return []
    pdir_p = Path(pdir)

    # 1. Native console_history.jsonl, if a future writer adds it.
    chf = pdir_p / 'console_history.jsonl'
    if chf.exists() and chf.stat().st_size > 0:
        out: list = []
        try:
            for line in chf.read_text(encoding='utf-8', errors='replace').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    out.append({'text': line, 'stream': 'stdout', 'ts': ''})
            if out:
                return out[-limit:]
        except Exception:
            pass

    # 2. Gearbox scan.log (universal Section 13 structure).
    sl = pdir_p / 'scan.log'
    if sl.exists() and sl.stat().st_size > 0:
        try:
            lines = sl.read_text(encoding='utf-8', errors='replace').splitlines()
            out = []
            for line in lines[-limit:]:
                if not line.strip():
                    continue
                # scan.log lines start with "[YYYY-MM-DD HH:MM:SS] ..." per
                # Gearbox convention — pull the ts when present.
                ts = ''
                m  = line[:1] == '['
                if m:
                    rb = line.find(']')
                    if 0 < rb < 32:
                        ts = line[1:rb]
                stream = 'stderr' if any(w in line.lower() for w in
                                         ('error', 'fail', 'exception',
                                          'fatal', 'critical')) else 'stdout'
                out.append({'text': line, 'stream': stream, 'ts': ts})
            if out:
                return out
        except Exception:
            pass

    # 3. gearbox_log.jsonl — Gauntlet-written structured log.
    gj = pdir_p / 'gearbox_log.jsonl'
    if gj.exists() and gj.stat().st_size > 0:
        try:
            entries = []
            for line in gj.read_text(encoding='utf-8', errors='replace').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    lvl = (e.get('level') or 'INFO').upper()
                    stream = 'stderr' if lvl in ('ERROR', 'EXCEPTION',
                                                  'FATAL', 'CRITICAL',
                                                  'TOOL_ERROR') else 'stdout'
                    msg = e.get('message') or ''
                    if e.get('tool'):
                        msg = f"[{e['tool']}] {msg}"
                    entries.append({'text': msg, 'stream': stream,
                                    'ts': e.get('ts', '')})
                except Exception:
                    pass
            if entries:
                return entries[-limit:]
        except Exception:
            pass

    # 4. Last resort — scan any *.log files in the project directory.
    scan = _scan_log_files_from_dir(project_id)
    if scan:
        return [{'text': e.get('message', ''),
                 'stream': 'stderr' if e.get('level') == 'ERROR' else 'stdout',
                 'ts':     e.get('ts', '')}
                for e in scan][-limit:]
    return []


@app.route('/api/console_history/<project_id>')
def api_console_history(project_id):
    entries = _console_buffer.get(project_id, [])
    if not entries:
        # Discovered projects (and projects whose Gauntlet process restarted)
        # have no live buffer — reconstruct from on-disk scan.log/gearbox_log.
        entries = _load_console_history_from_disk(project_id)
    return jsonify({'entries': entries})

@app.route('/api/errors/<project_id>')
def api_errors(project_id):
    entries = _error_buffer.get(project_id, [])
    if not entries:
        entries = _load_log_from_disk(project_id, 'errors.jsonl')
    return jsonify({'entries': entries})

@app.route('/api/delete_finding', methods=['POST'])
def delete_finding():
    """Move a finding to deleted_findings.jsonl and remove from findings.jsonl."""
    d          = request.get_json(force=True) or {}
    project_id = d.get('project_id', '')
    finding_id = d.get('finding_id', '')
    if not project_id or not finding_id:
        return jsonify({'error': 'project_id and finding_id required'}), 400
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    yaml_path   = pinfo.get('yaml_path', '')
    project_dir = os.path.dirname(os.path.abspath(yaml_path))
    findings_file = os.path.join(project_dir, 'findings.jsonl')
    deleted_file  = os.path.join(project_dir, 'deleted_findings.jsonl')
    kept    = []
    removed = None
    if os.path.exists(findings_file):
        with open(findings_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get('id') == finding_id:
                        removed = obj
                        removed['deleted_at'] = _ts()
                    else:
                        kept.append(line)
                except Exception:
                    kept.append(line)
    if removed is None:
        return jsonify({'error': 'Finding not found'}), 404
    with open(findings_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(kept) + ('\n' if kept else ''))
    with open(deleted_file, 'a', encoding='utf-8') as f:
        f.write(json.dumps(removed) + '\n')
    socketio.emit('finding_deleted', {'finding_id': finding_id},
                  room=_room(project_id))
    return jsonify({'success': True})


# ── False-positive management ────────────────────────────────────────────────
# Uses /opt/pr0t31n/shared/pr0t31n_false_positives.py.
# Mark removes the finding from findings.jsonl + findings.csv, appends it to
# false_positives.json + false_positives.csv. Recover does the reverse.

_GB_FP_CSV_FIELDS = [
    "id", "title", "datetime", "ip", "port", "hostname", "risk",
    "command", "description", "output", "cves", "sources", "service",
    "output_file", "affected", "owasp", "nist", "remediation",
]


def _gb_get_project_dir(project_id):
    """Resolve a project's directory from its registry entry."""
    pinfo = load_projects().get('projects', {}).get(project_id)
    if not pinfo:
        return None
    yaml_path = pinfo.get('yaml_path', '')
    return Path(os.path.dirname(os.path.abspath(yaml_path)))


def _gb_load_fp_helper():
    """Lazy-import shared false-positives helper. Returns module or None."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_false_positives as _fp
        return _fp
    except ImportError:
        return None


def _gb_remove_from_jsonl(findings_file, finding_id):
    if not os.path.exists(findings_file):
        return None
    kept, removed = [], None
    with open(findings_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if removed is None and obj.get('id') == finding_id:
                    removed = obj
                    continue
            except Exception:
                pass
            kept.append(line)
    if removed is not None:
        with open(findings_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(kept) + ('\n' if kept else ''))
    return removed


def _gb_append_to_jsonl(findings_file, finding):
    fid = finding.get('id')
    if fid and os.path.exists(findings_file):
        with open(findings_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    if json.loads(line).get('id') == fid:
                        return False
                except Exception:
                    continue
    with open(findings_file, 'a', encoding='utf-8') as f:
        f.write(json.dumps(finding) + '\n')
    return True


def _gb_remove_from_csv(csv_file, finding_id):
    if not os.path.exists(csv_file):
        return False
    import csv as _csv
    with open(csv_file, newline='', encoding='utf-8') as fh:
        rows = list(_csv.DictReader(fh))
    kept = [r for r in rows if r.get('id') != finding_id]
    if len(kept) == len(rows):
        return False
    fieldnames = list(rows[0].keys()) if rows else _GB_FP_CSV_FIELDS
    with open(csv_file, 'w', newline='', encoding='utf-8') as fh:
        wr = _csv.DictWriter(fh, fieldnames=fieldnames, extrasaction='ignore')
        wr.writeheader()
        wr.writerows(kept)
    return True


def _gb_append_to_csv(csv_file, finding, fieldnames):
    import csv as _csv
    new_file = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0
    with open(csv_file, 'a', newline='', encoding='utf-8') as fh:
        wr = _csv.DictWriter(fh, fieldnames=fieldnames, extrasaction='ignore')
        if new_file:
            wr.writeheader()
        wr.writerow(finding)


@app.route('/api/mark_false_positive', methods=['POST'])
def api_mark_false_positive():
    """Move a finding from findings.{jsonl,csv} to false_positives.{json,csv}."""
    d          = request.get_json(force=True) or {}
    project_id = d.get('project_id', '')
    finding_id = d.get('finding_id', '')
    if not project_id or not finding_id:
        return jsonify({'error': 'project_id and finding_id required'}), 400
    project_dir = _gb_get_project_dir(project_id)
    if project_dir is None:
        return jsonify({'error': 'Project not found'}), 404
    fp_helper = _gb_load_fp_helper()
    if fp_helper is None:
        return jsonify({'error': 'pr0t31n_false_positives helper not installed'}), 500
    findings_jsonl = str(project_dir / 'findings.jsonl')
    findings_csv   = str(project_dir / 'findings.csv')
    removed = _gb_remove_from_jsonl(findings_jsonl, finding_id)
    if removed is None:
        return jsonify({'error': 'Finding not found in findings.jsonl'}), 404
    removed['marked_fp_at'] = _ts()
    _gb_remove_from_csv(findings_csv, finding_id)
    fp_helper.add_false_positive(str(project_dir), removed,
                                  csv_fieldnames=_GB_FP_CSV_FIELDS)
    socketio.emit('finding_marked_fp',
                  {'finding_id': finding_id, 'finding': removed},
                  room=_room(project_id))
    return jsonify({'success': True, 'finding': removed})


@app.route('/api/recover_false_positive', methods=['POST'])
def api_recover_false_positive():
    """Move a finding from false_positives.{json,csv} back to findings.{jsonl,csv}."""
    d          = request.get_json(force=True) or {}
    project_id = d.get('project_id', '')
    finding_id = d.get('finding_id', '')
    if not project_id or not finding_id:
        return jsonify({'error': 'project_id and finding_id required'}), 400
    project_dir = _gb_get_project_dir(project_id)
    if project_dir is None:
        return jsonify({'error': 'Project not found'}), 404
    fp_helper = _gb_load_fp_helper()
    if fp_helper is None:
        return jsonify({'error': 'pr0t31n_false_positives helper not installed'}), 500
    recovered = fp_helper.remove_false_positive(str(project_dir), finding_id,
                                                  csv_fieldnames=_GB_FP_CSV_FIELDS)
    if recovered is None:
        return jsonify({'error': 'Finding not found in false_positives.json'}), 404
    recovered.pop('marked_fp_at', None)
    _gb_append_to_jsonl(str(project_dir / 'findings.jsonl'), recovered)
    _gb_append_to_csv(str(project_dir / 'findings.csv'), recovered, _GB_FP_CSV_FIELDS)
    socketio.emit('finding_recovered',
                  {'finding_id': finding_id, 'finding': recovered},
                  room=_room(project_id))
    return jsonify({'success': True, 'finding': recovered})


@app.route('/api/false_positives/<project_id>')
def api_false_positives_list(project_id):
    """List all false-positive findings for a project."""
    project_dir = _gb_get_project_dir(project_id)
    if project_dir is None:
        return jsonify({'false_positives': []}), 404
    fp_helper = _gb_load_fp_helper()
    if fp_helper is None:
        return jsonify({'false_positives': []})
    return jsonify({'false_positives': fp_helper.load_false_positives(str(project_dir))})


# ─── Device-Intelligence panel (shared aggregator) ───────────────────────
@app.route('/api/intel/<project_id>')
def api_intel(project_id):
    """Aggregated device/network intelligence for Gearbox runs — uses the
    shared aggregator_network on the producer's findings.jsonl converted to
    a list of dicts on the fly."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_intel as intel
    except ImportError:
        return jsonify({"error": "pr0t31n_intel not installed"}), 500
    pdir = _gb_get_project_dir(project_id)
    if pdir is None:
        return jsonify({"error": "project not found"}), 404
    # Read findings — prefer the universal findings.json (post-synthesis),
    # fall back to flattening findings.jsonl
    pdir_p = pdir if isinstance(pdir, Path) else Path(pdir)
    universal = pdir_p / "findings.json"
    if universal.exists():
        try:
            data = json.loads(universal.read_text(encoding="utf-8"))
            findings = data if isinstance(data, list) else []
        except Exception:
            findings = []
    else:
        findings = []
        jsonl = pdir_p / "findings.jsonl"
        if jsonl.exists():
            for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line: continue
                try: findings.append(json.loads(line))
                except: pass
    # Build synthetic hosts/services from finding ip/port pairs
    hosts = sorted({(f.get("ip") or f.get("affected_host", "")) for f in findings
                    if isinstance(f, dict) and (f.get("ip") or f.get("affected_host"))} - {""})
    hosts_inv = [{"ip": h} for h in hosts]
    services = []
    for f in findings:
        if not isinstance(f, dict): continue
        ip = f.get("ip") or f.get("affected_host", "")
        port = f.get("port") or f.get("affected_port", 0)
        if ip and port:
            try: services.append({"ip": ip, "port": int(port)})
            except (ValueError, TypeError): pass
    return jsonify(intel.aggregator_network(findings, hosts_inv, services))


@app.route('/api/deleted_findings/<project_id>')
def api_deleted_findings(project_id):
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'findings': []}), 404
    yaml_path    = pinfo.get('yaml_path', '')
    project_dir  = os.path.dirname(os.path.abspath(yaml_path))
    deleted_file = os.path.join(project_dir, 'deleted_findings.jsonl')
    findings = []
    if os.path.exists(deleted_file):
        with open(deleted_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        pass
    return jsonify({'findings': findings})

@app.route('/api/subprocesses/<project_id>')
def api_subprocesses(project_id):
    """
    Return the full process tree rooted at the gearbox subprocess.
    Uses /proc on Linux or psutil if available.
    Each entry: {pid, ppid, cmd, status}
    """
    proc = _active_procs.get(project_id)
    if not proc:
        return jsonify({'processes': [], 'root_pid': None})

    root_pid = proc.pid
    processes = []

    # Try psutil first — most complete
    try:
        import psutil as _ps
        try:
            root = _ps.Process(root_pid)
            for p in [root] + root.children(recursive=True):
                try:
                    processes.append({
                        'pid':    p.pid,
                        'ppid':   p.ppid(),
                        'cmd':    ' '.join(p.cmdline()) or p.name(),
                        'status': p.status(),
                    })
                except (_ps.NoSuchProcess, _ps.AccessDenied):
                    pass
        except (_ps.NoSuchProcess, _ps.AccessDenied):
            pass
    except ImportError:
        # Fallback: parse /proc on Linux
        try:
            import glob as _glob
            def _get_children(ppid):
                children = []
                for stat in _glob.glob('/proc/[0-9]*/stat'):
                    try:
                        with open(stat) as f:
                            fields = f.read().split()
                        pid_  = int(fields[0])
                        ppid_ = int(fields[3])
                        if ppid_ == ppid:
                            children.append(pid_)
                    except Exception:
                        pass
                return children

            def _cmd_of(pid):
                try:
                    with open(f'/proc/{pid}/cmdline', 'rb') as f:
                        return f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
                except Exception:
                    return f'[pid {pid}]'

            def _walk(pid):
                cmd = _cmd_of(pid)
                processes.append({'pid': pid, 'ppid': None, 'cmd': cmd, 'status': 'running'})
                for child in _get_children(pid):
                    _walk(child)

            _walk(root_pid)
        except Exception:
            # Last resort: just return root
            processes.append({
                'pid':    root_pid,
                'ppid':   None,
                'cmd':    f'gearbox (pid {root_pid})',
                'status': 'running',
            })

    return jsonify({'processes': processes, 'root_pid': root_pid})


@app.route('/api/kill_subprocess', methods=['POST'])
def api_kill_subprocess():
    """
    Kill a specific subprocess by PID.
    Only PIDs that are descendants of the active gearbox process are permitted.
    """
    import signal as _sig
    d          = request.get_json(force=True) or {}
    project_id = d.get('project_id', '')
    pid        = d.get('pid')
    if not project_id or not pid:
        return jsonify({'error': 'project_id and pid required'}), 400

    proc = _active_procs.get(project_id)
    if not proc:
        return jsonify({'error': 'No active gearbox process for this project'}), 404

    root_pid = proc.pid
    pid      = int(pid)

    # Verify the PID is a descendant of the root gearbox process
    allowed_pids = {root_pid}
    try:
        import psutil as _ps
        try:
            root = _ps.Process(root_pid)
            allowed_pids.update(c.pid for c in root.children(recursive=True))
        except Exception:
            pass
    except ImportError:
        # On Linux, walk /proc to collect descendants
        try:
            import glob as _glob
            def _descendants(ppid, seen=None):
                if seen is None:
                    seen = set()
                for stat in _glob.glob('/proc/[0-9]*/stat'):
                    try:
                        with open(stat) as f:
                            fields = f.read().split()
                        child_pid  = int(fields[0])
                        child_ppid = int(fields[3])
                        if child_ppid == ppid and child_pid not in seen:
                            seen.add(child_pid)
                            _descendants(child_pid, seen)
                    except Exception:
                        pass
                return seen
            allowed_pids.update(_descendants(root_pid))
        except Exception:
            pass

    if pid not in allowed_pids:
        return jsonify({'error': f'PID {pid} is not a child of gearbox process {root_pid}'}), 403

    try:
        os.kill(pid, _sig.SIGTERM)
        return jsonify({'success': True, 'pid': pid, 'signal': 'SIGTERM'})
    except ProcessLookupError:
        return jsonify({'error': f'PID {pid} not found'}), 404
    except PermissionError:
        # Try SIGKILL via sudo if SIGTERM was denied
        try:
            result = subprocess.run(
                ['sudo', '-n', 'kill', '-9', str(pid)],
                capture_output=True, timeout=5)
            if result.returncode == 0:
                return jsonify({'success': True, 'pid': pid, 'signal': 'SIGKILL (sudo)'})
        except Exception:
            pass
        return jsonify({'error': f'Permission denied to kill PID {pid}'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/evidence_tree/<project_id>')
def api_evidence_tree(project_id):
    """Return the live evidence file tree for dynamic evidence tab refresh."""
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Not found'}), 404
    pinfo = dict(pinfo, id=project_id)
    enriched = enrich_project(pinfo)
    if not enriched:
        return jsonify({'error': 'Could not load project'}), 404
    pmap = enriched.get('progress_map', {})
    return jsonify({
        'progress_map':        pmap,
        'module_status':       enriched.get('progress', {}).get('module_status', {}),
        'total_modules':       enriched['total_modules'],
        'completed_modules':   enriched['completed_modules'],
        'total_instances':     len(pmap),
        'completed_instances': sum(1 for i in pmap.values() if i.get('completed')),
    })


@app.route('/api/live_progress/<project_id>')
def api_live_progress(project_id):
    """
    Lightweight endpoint for real-time progress polling from the testing tab.
    Reads directly from the on-disk progress.json without full enrichment.
    """
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Not found'}), 404
    yaml_path = pinfo.get('yaml_path', '')
    try:
        yaml_data     = load_yaml(yaml_path)
        progress_data = load_progress(yaml_path)
        pmap          = compute_progress(yaml_data, progress_data,
                                         active_project_id=project_id)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    total_mods = sum(i['module_count'] for i in pmap.values())
    comp_mods  = sum(i['completed_count'] for i in pmap.values())
    total_inst = len(pmap)
    comp_inst  = sum(1 for i in pmap.values() if i.get('completed'))

    return jsonify({
        'total_modules':       total_mods,
        'completed_modules':   comp_mods,
        'total_instances':     total_inst,
        'completed_instances': comp_inst,
        'progress_map':        {k: {
            'completed':       v['completed'],
            'completed_count': v['completed_count'],
            'module_count':    v['module_count'],
            'module_statuses': v['module_statuses'],
        } for k, v in pmap.items()},
    })


# ─── API: Findings ─────────────────────────────────────────────────────────────

@app.route('/api/read_file', methods=['POST'])
def api_read_file():
    """
    Read and return the content of an output file for display in the findings modal.
    Security: path must be within the project's designated directory.
    """
    d          = request.get_json(force=True) or {}
    file_path  = d.get('path', '').strip()
    project_id = d.get('project_id', '')

    if not file_path:
        return jsonify({'error': 'No path provided'}), 400

    # Resolve and validate path
    try:
        abs_path = Path(os.path.abspath(file_path))
    except Exception:
        return jsonify({'error': 'Invalid path'}), 400

    # Security: ensure the file is within a known project directory
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if pinfo:
        yaml_path   = pinfo.get('yaml_path', '')
        project_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))
        if not str(abs_path).startswith(str(project_dir)):
            return jsonify({'error': 'Access denied — file outside project directory'}), 403
    else:
        # If project_id not found, still allow if path looks reasonable
        if '..' in file_path:
            return jsonify({'error': 'Access denied'}), 403

    if not abs_path.exists():
        return jsonify({'error': f'File not found: {abs_path.name}'}), 404

    try:
        size = abs_path.stat().st_size
        if size > 5_000_000:  # 5 MB limit
            return jsonify({'content': f'[File too large to display: {size:,} bytes]\n'
                                       f'Path: {abs_path}'}), 200
        if abs_path.suffix.lower() == '.pcap':
            content = _pcap_to_text(str(abs_path))
        else:
            content = abs_path.read_text(encoding='utf-8', errors='replace')
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export_zip/<project_id>')
def api_export_zip(project_id):
    """
    Zip the entire project directory and stream it as a download.

    Streams with an explicit Content-Length and a generator so Werkzeug's
    dev server cleanly terminates the HTTPS response — without this, Chrome
    reports ERR_INCOMPLETE_CHUNKED_ENCODING ("Check Internet Connection")
    on the download. The tempfile is deleted after the response is sent.
    """
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    yaml_path = Path(pinfo.get('yaml_path', ''))
    if not yaml_path.exists():
        return jsonify({'error': 'Project YAML not found'}), 404

    project_dir = yaml_path.parent
    if not project_dir.is_dir():
        return jsonify({'error': 'Project directory not found'}), 404

    # Build zip filename
    try:
        import yaml as _yaml
        with open(str(yaml_path), encoding='utf-8') as _f:
            _y = _yaml.safe_load(_f) or {}
    except Exception:
        _y = {}
    cs = re.sub(r'[^a-zA-Z0-9_-]', '', (_y.get('client_short') or 'client')).lower()
    dv = re.sub(r'[^a-zA-Z0-9_-]', '_', (_y.get('device') or 'device')).lower()
    dt = datetime.now().strftime('%Y%m%d%H%M')
    zip_name = f"gauntlet-{cs}-{dv}-{dt}.zip"

    import tempfile, zipfile
    tmp = tempfile.NamedTemporaryFile(suffix='.zip', delete=False, prefix='gauntlet_export_')
    tmp.close()
    tmp_path = tmp.name
    try:
        with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for fpath in project_dir.rglob('*'):
                if not fpath.is_file():
                    continue
                # Skip symlinks and special files — they can hang the zip writer
                try:
                    if fpath.is_symlink():
                        continue
                except OSError:
                    continue
                try:
                    arcname = fpath.relative_to(project_dir.parent)
                    zf.write(str(fpath), str(arcname))
                except (OSError, PermissionError):
                    # Skip files we can't read (broken symlinks, locked DBs, etc.)
                    continue
        file_size = os.path.getsize(tmp_path)
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return jsonify({'error': f'Failed to build zip: {e}'}), 500

    @after_this_request
    def _cleanup(response):
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return response

    def _stream():
        with open(tmp_path, 'rb') as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                yield chunk

    headers = {
        'Content-Disposition': f'attachment; filename="{zip_name}"',
        'Content-Length':      str(file_size),
        'Content-Type':        'application/zip',
        'Cache-Control':       'no-store',
        'X-Accel-Buffering':   'no',
    }
    return Response(_stream(), status=200, headers=headers,
                    mimetype='application/zip', direct_passthrough=True)


@app.route('/api/reset_project/<project_id>', methods=['DELETE'])
def api_reset_project(project_id):
    """Delete all files in the project directory except the YAML config."""
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    yaml_path = Path(pinfo.get('yaml_path', ''))
    if not yaml_path.exists():
        return jsonify({'error': 'Project YAML not found'}), 404

    project_dir = yaml_path.parent
    if not project_dir.is_dir():
        return jsonify({'error': 'Project directory not found'}), 404

    deleted = 0
    errors  = []
    for item in project_dir.iterdir():
        if item.resolve() == yaml_path.resolve():
            continue  # keep the YAML
        try:
            if item.is_dir():
                shutil.rmtree(str(item))
            else:
                item.unlink()
            deleted += 1
        except Exception as e:
            errors.append(str(e))

    if errors:
        return jsonify({'ok': False, 'deleted': deleted, 'errors': errors}), 500
    return jsonify({'ok': True, 'deleted': deleted})


@app.route('/api/delete_project/<project_id>', methods=['DELETE'])
def api_delete_project(project_id):
    """Remove the project from the registry and delete its entire directory."""
    raw = load_projects()
    projects = raw.get('projects', {})
    pinfo = projects.get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    yaml_path = Path(pinfo.get('yaml_path', ''))
    project_dir = yaml_path.parent if yaml_path.exists() else None

    # Remove from project registry first
    del projects[project_id]
    try:
        save_projects(raw)
    except Exception as e:
        return jsonify({'error': f'Failed to update project registry: {e}'}), 500

    # Delete directory
    if project_dir and project_dir.is_dir():
        try:
            shutil.rmtree(str(project_dir))
        except Exception as e:
            return jsonify({'ok': True, 'warning': f'Project removed from index but directory deletion failed: {e}'})

    return jsonify({'ok': True})


@app.route('/api/import_yaml_path', methods=['POST'])
def api_import_yaml_path():
    """Register an existing project YAML by its absolute filesystem path."""
    body = request.get_json(silent=True) or {}
    yaml_path_str = (body.get('yaml_path') or '').strip()

    if not yaml_path_str:
        return jsonify({'error': 'yaml_path is required'}), 400

    yaml_path = Path(yaml_path_str)
    if not yaml_path.is_file():
        return jsonify({'error': f'File not found: {yaml_path_str}'}), 400
    if yaml_path.suffix.lower() not in ('.yaml', '.yml'):
        return jsonify({'error': 'File must be a .yaml or .yml file'}), 400

    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        return jsonify({'error': f'Failed to parse YAML: {e}'}), 400

    abs_path = str(yaml_path.resolve())

    # Check if this YAML is already registered
    raw = load_projects()
    projects = raw.get('projects', {})
    version = str(data.get('device_model_number', '') or '').strip()

    for pid, pinfo in projects.items():
        if str(Path(pinfo.get('yaml_path', '')).resolve()) == abs_path:
            # Already known — return existing entry so the UI can select it
            return jsonify({'project_id': pid, 'name': pinfo.get('name', ''),
                            'version': version, 'already_existed': True})

    project_id = str(uuid.uuid4())
    client     = data.get('client_name') or data.get('client_short') or 'Unknown Client'
    device     = data.get('device') or 'Unknown Device'
    name       = f"{client} — {device}"

    projects[project_id] = {
        'id':                      project_id,
        'name':                    name,
        'yaml_path':               abs_path,
        'created':                 datetime.now().strftime('%Y-%m-%d'),
        'device_model_number': version,
    }
    raw['projects'] = projects
    try:
        save_projects(raw)
    except Exception as e:
        return jsonify({'error': f'Failed to save project registry: {e}'}), 500

    return jsonify({'project_id': project_id, 'name': name,
                    'version': version, 'already_existed': False})


@app.route('/api/import_zip', methods=['POST'])
def api_import_zip():
    """
    Import a Gauntlet-exported project zip.

    The zip is expected to contain a single top-level directory holding the
    project YAML and all run output. The project is extracted into the
    canonical clients base and registered in the project registry.
    """
    import tempfile, zipfile

    upload = request.files.get('zipfile')
    if not upload or not upload.filename:
        return jsonify({'error': 'No zip file provided'}), 400

    fname = secure_filename(upload.filename)
    if not fname.lower().endswith('.zip'):
        return jsonify({'error': 'File must be a .zip'}), 400

    # Save upload to a tempfile so zipfile can seek
    tmp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False, prefix='gauntlet_import_')
    try:
        upload.save(tmp_zip.name)
        tmp_zip.close()
    except Exception as e:
        try: os.unlink(tmp_zip.name)
        except OSError: pass
        return jsonify({'error': f'Failed to save upload: {e}'}), 500

    try:
        if not zipfile.is_zipfile(tmp_zip.name):
            return jsonify({'error': 'Upload is not a valid zip file'}), 400

        with zipfile.ZipFile(tmp_zip.name, 'r') as zf:
            members = [m for m in zf.namelist() if m and not m.endswith('/')]
            if not members:
                return jsonify({'error': 'Zip is empty'}), 400

            # Determine the top-level directory inside the zip
            top_parts = {Path(m).parts[0] for m in members if Path(m).parts}
            if len(top_parts) != 1:
                return jsonify({'error': 'Zip must contain a single top-level project directory'}), 400
            top_dir = top_parts.pop()

            # Locate a YAML at the top of that directory
            yaml_candidates = [m for m in members
                               if Path(m).parts[:1] == (top_dir,)
                               and len(Path(m).parts) == 2
                               and Path(m).suffix.lower() in ('.yaml', '.yml')]
            if not yaml_candidates:
                return jsonify({'error': 'No project YAML found at top of zip'}), 400
            yaml_member = yaml_candidates[0]

            # Read the YAML up front to compute the destination
            try:
                yaml_text = zf.read(yaml_member).decode('utf-8', errors='replace')
                ydata     = yaml.safe_load(yaml_text) or {}
            except Exception as e:
                return jsonify({'error': f'Failed to parse YAML in zip: {e}'}), 400

            client_short = re.sub(r'[^\w-]', '_',
                                  (ydata.get('client_short') or 'project').strip().lower()).strip('_') or 'project'
            start_date = str(ydata.get('start_date') or '')
            year = (start_date[:4] if len(start_date) >= 4 and start_date[:4].isdigit()
                    else datetime.now().strftime('%Y'))

            dest_parent = _clients_base() / client_short / year / 'gearbox'
            try:
                dest_parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                dest_parent = Path.home() / 'clients' / client_short / year / 'gearbox'
                dest_parent.mkdir(parents=True, exist_ok=True)

            project_dir = dest_parent / top_dir
            if project_dir.exists():
                # Avoid clobbering — append a numeric suffix
                idx = 1
                while True:
                    candidate = dest_parent / f"{top_dir}_imported_{idx}"
                    if not candidate.exists():
                        project_dir = candidate
                        break
                    idx += 1

            project_dir.mkdir(parents=True, exist_ok=False)

            # Extract — rewrite arcnames so the zip's top dir becomes project_dir
            try:
                for member in zf.infolist():
                    name = member.filename
                    if not name or name.endswith('/'):
                        continue
                    if name.startswith(('/', '\\')) or ':' in name or '..' in Path(name).parts:
                        raise ValueError(f"Refusing unsafe zip entry: {name}")
                    rel_parts = Path(name).parts[1:]  # strip the top dir
                    if not rel_parts:
                        continue
                    target = (project_dir / Path(*rel_parts)).resolve()
                    try:
                        target.relative_to(project_dir.resolve())
                    except ValueError:
                        raise ValueError(f"Refusing zip entry that escapes dest: {name}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
            except Exception as e:
                # Clean up partial extraction
                try: shutil.rmtree(str(project_dir))
                except OSError: pass
                return jsonify({'error': f'Extraction failed: {e}'}), 400

        # Locate the extracted YAML on disk
        extracted_yaml = project_dir / Path(yaml_member).name
        if not extracted_yaml.is_file():
            # Fallback: scan project_dir for any yaml at top level
            ys = list(project_dir.glob('*.yaml')) + list(project_dir.glob('*.yml'))
            if not ys:
                try: shutil.rmtree(str(project_dir))
                except OSError: pass
                return jsonify({'error': 'Extracted project has no YAML'}), 500
            extracted_yaml = ys[0]

        abs_yaml = str(extracted_yaml.resolve())

        # Register in project registry (de-dupe on resolved YAML path)
        raw = load_projects()
        projects = raw.get('projects', {})
        version = str(ydata.get('device_model_number', '') or '').strip()

        for pid, pinfo in projects.items():
            if str(Path(pinfo.get('yaml_path', '')).resolve()) == abs_yaml:
                return jsonify({'project_id': pid, 'name': pinfo.get('name', ''),
                                'version': version, 'already_existed': True,
                                'project_dir': str(project_dir)})

        new_id = str(uuid.uuid4())
        client = ydata.get('client_name') or ydata.get('client_short') or 'Unknown Client'
        device = ydata.get('device') or 'Unknown Device'
        name   = f"{client} — {device}"

        projects[new_id] = {
            'id':                  new_id,
            'name':                name,
            'yaml_path':           abs_yaml,
            'created':             datetime.now().strftime('%Y-%m-%d'),
            'device_model_number': version,
        }
        raw['projects'] = projects
        try:
            save_projects(raw)
        except Exception as e:
            return jsonify({'error': f'Failed to save project registry: {e}'}), 500

        return jsonify({'project_id': new_id, 'name': name, 'version': version,
                        'already_existed': False, 'project_dir': str(project_dir)})

    finally:
        try: os.unlink(tmp_zip.name)
        except OSError: pass


@app.route('/api/targets/<project_id>')
def api_targets(project_id):
    """
    Return all observed IPs and open ports for a project from the gearbox SQLite DB.

    Response schema:
    {
      "observed_ips": [
        {"ip": "10.0.0.1", "sources": ["nmap","nessus"], "instances": [...]}
      ],
      "ports": {
        "10.0.0.1": [
          {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4"}
        ]
      }
    }
    """
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Not found'}), 404
    try:
        # Resolve directory via _project_dir_for (works for discovered
        # projects that have no top-level YAML).  Falling back to yaml_path
        # alone caused this route to silently return empty for discovered
        # projects since 1.0 — see the bug fix in v1.9.0.
        pdir = _project_dir_for(project_id)
        if not pdir:
            return jsonify({'observed_ips': [], 'ports': {}})
        project_dir = Path(pdir)
        yaml_path   = pinfo.get('yaml_path', '')
        if yaml_path and not os.path.isabs(yaml_path):
            yaml_path = os.path.join(_BASE_DIR, yaml_path)
        yaml_data: dict = {}
        if yaml_path and os.path.exists(yaml_path):
            try:
                yaml_data = load_yaml(yaml_path)
            except Exception:
                yaml_data = {}

        # Locate the gearbox SQLite DB — try stem-named first, then any .db in dir
        stem    = Path(yaml_path).stem if yaml_path else ''
        db_path = (project_dir / f"{stem}.db") if stem else None
        if not (db_path and db_path.exists()):
            # Search project dir and one level of subdirs
            dbs = sorted(project_dir.glob("*.db")) + sorted(project_dir.glob("*/*.db"))
            db_path = dbs[0] if dbs else None

        observed_ips: list[dict] = []
        ports_map:    dict       = {}
        csv_ips:      set        = set()

        # ── Read from SQLite DB ───────────────────────────────────────────
        if db_path and db_path.exists():
            import sqlite3 as _sqlite3
            conn = _sqlite3.connect(str(db_path), timeout=10)
            conn.row_factory = _sqlite3.Row

            # All discovered hosts (may have duplicates across instances)
            # Try to select enrichment columns; fall back gracefully if they don't exist yet
            try:
                rows = conn.execute(
                    "SELECT ip, subdevice, interface, instance, timestamp, "
                    "mac_address, hostname, os_name "
                    "FROM discovered_hosts ORDER BY ip, timestamp").fetchall()
                _has_enrichment = True
            except Exception:
                rows = conn.execute(
                    "SELECT ip, subdevice, interface, instance, timestamp "
                    "FROM discovered_hosts ORDER BY ip, timestamp").fetchall()
                _has_enrichment = False

            seen: dict = {}   # ip -> entry dict
            for r in rows:
                ip = r['ip']
                if ip not in seen:
                    seen[ip] = {
                        'ip':         ip,
                        'sources':    ['nmap'],
                        'instances':  [],
                        'first_seen': r['timestamp'],
                        'mac_address': (r['mac_address'] if _has_enrichment else None) or '',
                        'hostname':    (r['hostname']    if _has_enrichment else None) or '',
                        'os_name':     (r['os_name']     if _has_enrichment else None) or '',
                    }
                else:
                    # Update enrichment with any better data from other rows
                    if _has_enrichment:
                        if not seen[ip]['mac_address'] and r['mac_address']:
                            seen[ip]['mac_address'] = r['mac_address']
                        if not seen[ip]['hostname'] and r['hostname']:
                            seen[ip]['hostname'] = r['hostname']
                        if not seen[ip]['os_name'] and r['os_name']:
                            seen[ip]['os_name'] = r['os_name']
                inst = f"{r['subdevice']}.{r['interface']}.{r['instance']}"
                if inst not in seen[ip]['instances']:
                    seen[ip]['instances'].append(inst)

            # Open ports for every host
            port_rows = conn.execute(
                "SELECT ip, port, protocol, service, version, timestamp "
                "FROM open_ports ORDER BY ip, port").fetchall()
            for r in port_rows:
                ip = r['ip']
                ports_map.setdefault(ip, [])
                entry = {
                    'port':      r['port'],
                    'protocol':  r['protocol'] or 'tcp',
                    'service':   r['service']  or '',
                    'version':   r['version']  or '',
                    'timestamp': r['timestamp'],
                    'tools_run': [],   # populated below from evidence files
                }
                if entry not in ports_map[ip]:
                    ports_map[ip].append(entry)
                # Any host with ports is definitely from nmap/nessus
                if ip in seen and 'nmap' not in seen[ip]['sources']:
                    seen[ip]['sources'].append('nmap')

            conn.close()
            observed_ips = list(seen.values())

        # ── Also read from observed_ips.csv (tcpdump / IpTracker) ─────────
        csv_path = project_dir / 'observed_ips.csv'
        if csv_path.exists():
            try:
                import csv as _csv
                with open(csv_path, encoding='utf-8', newline='') as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        ip = (row.get('ip') or row.get('IP') or '').strip()
                        if not ip:
                            continue
                        csv_ips.add(ip)
                        existing = next((e for e in observed_ips if e['ip'] == ip), None)
                        if existing:
                            if 'tcpdump' not in existing['sources']:
                                existing['sources'].append('tcpdump')
                        else:
                            observed_ips.append({
                                'ip':         ip,
                                'sources':    ['tcpdump'],
                                'instances':  [],
                                'first_seen': row.get('timestamp', ''),
                                'mac_address': '',
                                'hostname':    '',
                                'os_name':     '',
                            })
            except Exception:
                pass

        # Sort by IP numerically
        def _ip_sort_key(entry):
            try:
                import ipaddress
                return int(ipaddress.ip_address(entry['ip']))
            except Exception:
                return 0

        observed_ips.sort(key=_ip_sort_key)
        for ip_data in observed_ips:
            if ip_data['ip'] not in ports_map:
                ports_map[ip_data['ip']] = []

        # ── Scan evidence files to determine which tools ran per IP/port ──
        # We look for filename patterns in the project output tree.
        # Tools that run against a specific port (filename has IP_PORT_ prefix)
        _PORT_TOOL_PATTERNS = [
            ('ssh-audit',  r'_ssh_audit\.'),
            ('sslscan',    r'_sslscan\.'),
            ('testssl',    r'_testssl\.'),
            ('shcheck',    r'_shcheck\.|shcheck'),
            ('nuclei',     r'_nuclei\.'),
            ('nmap',       r'_nmap_(?:ssh|smb|ftp|port|live)\.|_ports\.'),
        ]
        # Tools that run against the whole IP (no port in filename)
        _IP_TOOL_PATTERNS = [
            ('nessus',     r'nessus_results\.'),
            ('responder',  r'responder_stdout\.'),
            ('tcpdump',    r'_tcpdump\.pcap'),
            ('tshark',     r'_tshark\.'),
        ]
        import re as _re
        try:
            # Build ip->port->set(tools) index from filenames in project dir
            _ip_port_tools: dict  = {}   # ip -> port_str -> set(tools)
            _ip_level_tools: dict = {}   # ip -> set(tools) for IP-wide tools

            for f in project_dir.rglob('*'):
                if not f.is_file():
                    continue
                fname = f.name
                # Files like 192_168_1_1_443_sslscan.txt  (ip + port + tool)
                ip_port_m = _re.match(r'^(\d+_\d+_\d+_\d+)_(\d+)_', fname)
                # Files like 192_168_1_1_nessus_results.csv (ip-only)
                ip_only_m = _re.match(r'^(\d+_\d+_\d+_\d+)_(?!\d)', fname)

                if ip_port_m:
                    file_ip   = ip_port_m.group(1).replace('_', '.')
                    file_port = ip_port_m.group(2)
                    for tool, pat in _PORT_TOOL_PATTERNS:
                        if _re.search(pat, fname, _re.I):
                            _ip_port_tools.setdefault(file_ip, {})
                            _ip_port_tools[file_ip].setdefault(file_port, set()).add(tool)
                elif ip_only_m:
                    file_ip = ip_only_m.group(1).replace('_', '.')
                    for tool, pat in _IP_TOOL_PATTERNS:
                        if _re.search(pat, fname, _re.I):
                            _ip_level_tools.setdefault(file_ip, set()).add(tool)
                    # Also check port-level tools for ip-only files (e.g. nessus per port)
                    for tool, pat in _PORT_TOOL_PATTERNS:
                        if _re.search(pat, fname, _re.I):
                            _ip_level_tools.setdefault(file_ip, set()).add(tool)

            # Also scan for ip-level tool files without the strict ip_only pattern
            for f in project_dir.rglob('*'):
                if not f.is_file(): continue
                fname = f.name
                for tool, pat in _IP_TOOL_PATTERNS:
                    if _re.search(pat, fname, _re.I):
                        # try to find an IP in the path
                        for part in f.parts:
                            ip_m2 = _re.match(r'^(\d+_\d+_\d+_\d+)', part)
                            if ip_m2:
                                file_ip2 = ip_m2.group(1).replace('_', '.')
                                _ip_level_tools.setdefault(file_ip2, set()).add(tool)

            # Attach tools_run to each port entry (port-specific only)
            # Attach ip_tools_run to each observed_ip entry (ip-wide tools)
            for ip, port_list in ports_map.items():
                ip_port_map = _ip_port_tools.get(ip, {})
                for pentry in port_list:
                    port_str = str(pentry['port'])
                    # Only tools with files matching this specific port
                    port_tools = set(ip_port_map.get(port_str, set()))
                    port_tools.add('nmap')   # nmap always scanned this port
                    pentry['tools_run'] = sorted(port_tools)

            # Add IP-level tools to observed_ips entries
            for entry in observed_ips:
                ip = entry.get('ip','')
                entry['ip_tools'] = sorted(_ip_level_tools.get(ip, set()))
        except Exception:
            pass

        return jsonify({
            'observed_ips': observed_ips,
            'ports':        ports_map,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/update_finding_risk', methods=['POST'])
def api_update_finding_risk():
    """
    Change risk level of a finding.  Propagates to every storage layer:
      1. findings.jsonl  — canonical append-log (rewritten with updated risk)
      2. Every *.db file in the project tree (SQLite findings table)
      3. finding_risk_changes.jsonl  — human/Claude-readable audit trail
      4. risk_overrides.yaml  — re-run safe: gearbox reads this on startup
                                so a re-assessment preserves manual overrides
    Also broadcasts a socket event so all connected clients update live.
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '').strip()
    finding_id = data.get('finding_id', '').strip()
    new_risk   = data.get('risk', '').strip()

    VALID = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'}
    if new_risk not in VALID:
        return jsonify({'error': f'Invalid risk: {new_risk}'}), 400
    if not finding_id:
        return jsonify({'error': 'finding_id required'}), 400

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        jsonl_path  = project_dir / 'findings.jsonl'
        if not jsonl_path.exists():
            return jsonify({'error': 'findings.jsonl not found'}), 404

        # ── 1. Rewrite findings.jsonl ──────────────────────────────────────
        old_risk    = None
        title_found = ''
        raw_lines   = jsonl_path.read_text(errors='replace').splitlines()
        out_lines   = []
        for line in raw_lines:
            if not line.strip():
                out_lines.append(line)
                continue
            try:
                obj = json.loads(line)
                if obj.get('id') == finding_id:
                    old_risk    = obj.get('risk', '')
                    title_found = obj.get('title', '')
                    obj['risk'] = new_risk
                out_lines.append(json.dumps(obj))
            except Exception:
                out_lines.append(line)
        jsonl_path.write_text('\n'.join(out_lines) + '\n')

        # ── 2. Update every SQLite DB in the project tree ──────────────────
        import sqlite3 as _sq
        updated_dbs = 0
        for db_f in sorted(project_dir.rglob('*.db')):
            try:
                with _sq.connect(str(db_f), timeout=10) as cn:
                    cur = cn.execute(
                        'UPDATE findings SET risk=? WHERE id=?',
                        (new_risk, finding_id))
                    if cur.rowcount > 0:
                        updated_dbs += 1
            except Exception:
                pass

        # ── 3. Append to finding_risk_changes.jsonl ────────────────────────
        change_log = project_dir / 'finding_risk_changes.jsonl'
        change_entry = json.dumps({
            'ts':         datetime.now().isoformat(),
            'action':     'risk_change',
            'finding_id': finding_id,
            'title':      title_found,
            'old_risk':   old_risk,
            'new_risk':   new_risk,
        })
        with open(change_log, 'a', encoding='utf-8') as fh:
            fh.write(change_entry + '\n')

        # ── 4. Write/update risk_overrides.yaml ───────────────────────────
        # This file is read by gearbox on startup so manual risk changes
        # survive a re-assessment.  Format:
        #   overrides:
        #     - finding_id: <uuid>
        #       title: <title>
        #       risk: <new_risk>
        #       ts: <iso>
        overrides_path = project_dir / 'risk_overrides.yaml'
        try:
            if overrides_path.exists():
                import yaml as _yaml
                ov_data = _yaml.safe_load(
                    overrides_path.read_text(encoding='utf-8')) or {}
            else:
                ov_data = {}
            overrides = ov_data.get('overrides', [])
            # Update existing entry or append new one
            found_entry = False
            for entry in overrides:
                if entry.get('finding_id') == finding_id:
                    entry['risk'] = new_risk
                    entry['ts']   = datetime.now().isoformat()
                    found_entry   = True
                    break
            if not found_entry:
                overrides.append({
                    'finding_id': finding_id,
                    'title':      title_found,
                    'risk':       new_risk,
                    'ts':         datetime.now().isoformat(),
                })
            ov_data['overrides'] = overrides
            import yaml as _yaml
            overrides_path.write_text(
                _yaml.dump(ov_data, default_flow_style=False, allow_unicode=True),
                encoding='utf-8')
        except ImportError:
            # yaml not available — write a minimal JSON-compatible YAML manually
            overrides_path.write_text(
                f'# Risk overrides — applied by gearbox on startup\n'
                f'# finding_id: {finding_id}\n'
                f'# risk: {new_risk}\n',
                encoding='utf-8')
        except Exception:
            pass  # overrides file is best-effort

        # ── 5. Broadcast to all connected clients ─────────────────────────
        socketio.emit('finding_risk_updated',
                      {'id': finding_id, 'risk': new_risk, 'title': title_found},
                      room=_room(project_id))

        return jsonify({
            'ok':          True,
            'finding_id':  finding_id,
            'new_risk':    new_risk,
            'old_risk':    old_risk,
            'updated_dbs': updated_dbs,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/group_findings', methods=['POST'])
def api_group_findings():
    """
    Merge two or more findings into one grouped finding.
    - Writes the new finding to findings.jsonl (marking originals deleted)
    - Appends to finding_grouping_changes.jsonl for persistence tracking
    - Emits socket events so live UI updates
    """
    data         = request.get_json(force=True) or {}
    project_id   = data.get('project_id','').strip()
    finding_ids  = data.get('finding_ids', [])   # list of IDs to group
    new_title    = data.get('title','').strip()
    affected_items = data.get('affected', [])    # list of affected strings
    if not finding_ids or not new_title:
        return jsonify({'error': 'finding_ids and title required'}), 400
    raw   = load_projects()
    pinfo = raw.get('projects',{}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    try:
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        jsonl_path  = project_dir / 'findings.jsonl'
        if not jsonl_path.exists():
            return jsonify({'error': 'findings.jsonl not found'}), 404
        raw_lines = jsonl_path.read_text(errors='replace').splitlines()
        # Collect originals
        originals  = []
        out_files  = []
        best_risk  = 'Informational'
        _RISK_ORD  = {'Critical':0,'High':1,'Medium':2,'Low':3,'Informational':4,'Unknown':5}
        for line in raw_lines:
            if not line.strip(): continue
            try:
                obj = json.loads(line)
                if obj.get('id') in finding_ids:
                    originals.append(obj)
                    for fp in (obj.get('output_files') or []):
                        if fp and fp not in out_files: out_files.append(fp)
                    if fp := obj.get('output_file'):
                        if fp not in out_files: out_files.append(fp)
                    if _RISK_ORD.get(obj.get('risk','Unknown'),5) < _RISK_ORD.get(best_risk,5):
                        best_risk = obj.get('risk','Informational')
            except Exception: pass
        if not originals:
            return jsonify({'error': 'None of the finding IDs found'}), 404
        # Build grouped finding (use first original as template)
        import uuid as _uuid
        first = originals[0]
        grouped = dict(first)
        grouped['id']       = str(_uuid.uuid4())
        grouped['title']    = new_title
        grouped['risk']     = best_risk
        grouped['affected'] = affected_items
        grouped['output_files'] = out_files
        grouped['output_file']  = out_files[0] if out_files else ''
        grouped['timestamp']    = datetime.now().isoformat()
        grouped['tools_used']   = list({t for o in originals
                                        for t in (o.get('tools_used') or [])})
        # Write: remove originals from findings.jsonl, append grouped
        new_lines   = []
        deleted_out = []
        ts_now      = datetime.now().isoformat()
        for line in raw_lines:
            if not line.strip(): continue
            try:
                obj = json.loads(line)
                if obj.get('id') in finding_ids:
                    # Move original to deleted_findings.jsonl (with audit markers)
                    obj['_grouped_into'] = grouped['id']
                    obj['deleted_at']    = ts_now
                    deleted_out.append(json.dumps(obj))
                    # Do NOT add to new_lines — original is fully removed
                else:
                    new_lines.append(line)
            except Exception:
                new_lines.append(line)
        new_lines.append(json.dumps(grouped))
        jsonl_path.write_text('\n'.join(new_lines) + '\n')
        # Persist originals to deleted_findings.jsonl
        deleted_file = project_dir / 'deleted_findings.jsonl'
        with open(deleted_file, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(deleted_out) + '\n')
        # DB: delete originals, insert grouped
        try:
            for db_f in project_dir.rglob('*.db'):
                import sqlite3 as _sq
                with _sq.connect(str(db_f), timeout=10) as cn:
                    cn.executemany('DELETE FROM findings WHERE id=?',
                                  [(fid,) for fid in finding_ids])
                break
        except Exception: pass
        # Write grouping change log
        change_log = project_dir / 'finding_grouping_changes.jsonl'
        entry = json.dumps({
            'ts':            datetime.now().isoformat(),
            'action':        'group',
            'new_title':     new_title,
            'new_id':        grouped['id'],
            'new_risk':      best_risk,
            'affected':      affected_items,
            'originals':     [{'id': o['id'], 'title': o.get('title',''),
                               'risk': o.get('risk',''), 'ip': o.get('ip',''),
                               'port': o.get('port',''),
                               'output_files': o.get('output_files',[])
                               } for o in originals],
            'combined_output_files': out_files,
        })
        with open(change_log, 'a') as fh:
            fh.write(entry + '\n')
        socketio.emit('findings_grouped', {
            'removed_ids': finding_ids,
            'new_finding': grouped,
        }, room=_room(project_id))
        return jsonify({'ok': True, 'new_finding': grouped})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rename_finding', methods=['POST'])
def api_rename_finding():
    """
    Rename a finding — propagate to ALL storage locations:
      • findings.jsonl          (every line matching the id)
      • All *.db SQLite files   (findings table, all databases in project tree)
      • finding_name_changes.jsonl  (audit log for gearbox persistence)
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id','').strip()
    finding_id = data.get('finding_id','').strip()
    new_title  = data.get('title','').strip()
    if not finding_id:
        return jsonify({'error': 'finding_id required'}), 400
    if not new_title:
        return jsonify({'error': 'title required'}), 400
    raw   = load_projects()
    pinfo = raw.get('projects',{}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    try:
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        jsonl_path  = project_dir / 'findings.jsonl'
        if not jsonl_path.exists():
            return jsonify({'error': 'findings.jsonl not found'}), 404

        # ── 1. Rewrite findings.jsonl — update EVERY line with this id ────
        raw_lines = jsonl_path.read_text(errors='replace').splitlines()
        old_title = None
        out_lines = []
        for line in raw_lines:
            if not line.strip():
                out_lines.append(line)
                continue
            try:
                obj = json.loads(line)
                if obj.get('id') == finding_id:
                    if old_title is None:
                        old_title = obj.get('title', '')
                    obj['title'] = new_title
                out_lines.append(json.dumps(obj))
            except Exception:
                out_lines.append(line)
        jsonl_path.write_text('\n'.join(out_lines) + '\n')

        # ── 2. Update ALL SQLite databases in the project tree ────────────
        import sqlite3 as _sq
        db_updated = 0
        for db_f in sorted(project_dir.rglob('*.db')):
            try:
                with _sq.connect(str(db_f), timeout=10) as cn:
                    # Check if findings table exists in this db
                    tbl = cn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name='findings'"
                    ).fetchone()
                    if tbl:
                        cur = cn.execute(
                            'UPDATE findings SET title=? WHERE id=?',
                            (new_title, finding_id))
                        if cur.rowcount > 0:
                            db_updated += 1
            except Exception:
                pass

        # ── 3. Append to finding_name_changes.jsonl (gearbox audit log) ──
        if old_title is not None and old_title != new_title:
            change_log = project_dir / 'finding_name_changes.jsonl'
            entry = json.dumps({
                'ts':          datetime.now().isoformat(),
                'finding_id':  finding_id,
                'old_title':   old_title,
                'new_title':   new_title,
                'instruction': (
                    f'In gearbox.py FindingManager: if a finding with id '
                    f'"{finding_id}" or title "{old_title}" is created or '
                    f'persisted, rename it to "{new_title}" instead.'
                ),
            })
            with open(str(change_log), 'a', encoding='utf-8') as fh:
                fh.write(entry + '\n')

        socketio.emit('finding_renamed',
                      {'id': finding_id, 'title': new_title},
                      room=_room(project_id))
        return jsonify({
            'ok':        True,
            'old_title': old_title,
            'db_count':  db_updated,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/findings/<project_id>')
def api_findings(project_id):
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': f'Project {project_id!r} not found'}), 404
    # Resolve project directory: prefer the discovery-time project_dir, fall
    # back to dirname(yaml_path) for projects created via new_project.
    # Discovered projects may legitimately have no YAML — don't 500 on them.
    pdir = _project_dir_for(project_id)
    if not pdir:
        return jsonify({'error':
            'Project has no resolvable directory (neither project_dir nor yaml_path)'}), 500
    # load_findings only uses dirname(yaml_path) to find findings.jsonl, so
    # synthesise a placeholder path that points at the resolved directory.
    yaml_path = pinfo.get('yaml_path', '') or os.path.join(pdir, '_gauntlet.yaml')
    if not os.path.isabs(yaml_path):
        yaml_path = os.path.join(_BASE_DIR, yaml_path)
    findings = load_findings(yaml_path)
    _RISK_ORDER = {'Critical':0,'High':1,'Medium':2,'Low':3,'Informational':4,'Unknown':5}
    findings.sort(key=lambda f: (_RISK_ORDER.get(f.get('risk','Unknown'), 5),
                                  f.get('title','').lower()))
    return jsonify({'findings': findings, 'count': len(findings)})


# ─── API: Clear Module ─────────────────────────────────────────────────────────

@app.route('/api/clear_module', methods=['POST'])
def clear_module():
    """
    Reset a module to pending and archive its evidence to deleted/.
    Returns {ok, archived: [...]} on success.
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '')
    sd_key     = data.get('sd_key', '')
    interface  = data.get('interface', '')
    inst_key   = data.get('inst_key', '')
    module     = data.get('module', '')

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        import fnmatch as _fn
        yaml_path   = pinfo.get('yaml_path', '')
        yaml_data   = load_yaml(yaml_path)
        project_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))

        # Archive evidence files
        target_dir, _ = _module_target_dir(
            yaml_data, yaml_path, sd_key, interface, inst_key, module)
        evidence_entries = _mod_evidence(module)
        patterns = [p for e in evidence_entries for p in e.get('patterns', [])]

        deleted_dir = project_dir / 'deleted'
        archived = []
        if target_dir.exists():
            for f in list(target_dir.iterdir()):
                if f.is_file() and (not patterns or
                        any(_fn.fnmatch(f.name, p) for p in patterns)):
                    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                    deleted_dir.mkdir(exist_ok=True)
                    dest = deleted_dir / f"{f.stem}__{ts}{f.suffix}"
                    shutil.move(str(f), str(dest))
                    archived.append(str(dest.relative_to(project_dir)))

        # Reset module status — write to project_dir/progress.json
        progress_file = str(project_dir / 'progress.json')
        progress_data = load_progress(yaml_path)
        module_status = progress_data.setdefault('module_status', {})
        iid     = f"{sd_key}.{interface}.{inst_key}"
        mod_key = f"{iid}.{module}"
        if mod_key in module_status:
            del module_status[mod_key]

        # Remove instance from completed_instances
        completed = set(progress_data.get('completed_instances', []))
        completed.discard(iid)
        progress_data['completed_instances'] = list(completed)

        with open(progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, indent=2)

        # Notify connected clients so badge resets to 'pending' live
        room = _room(project_id)
        socketio.emit('module_status', {
            'subdevice': sd_key,
            'interface': interface,
            'instance':  inst_key,
            'module':    module,
            'status':    'pending',
            'detail':    '',
        }, room=room)

        return jsonify({'ok': True, 'archived': archived})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _module_target_dir(yaml_data: dict, yaml_path: str,
                       sd_key: str, interface: str, inst_key: str,
                       module: str) -> tuple:
    """
    Return (target_directory, file_prefix) for a given module instance,
    matching gearbox.py's directory layout exactly.

    Handles both list-based and dict-based subdevices YAML formats.
    Path structure: project_dir / CLIENT_SHORT / device / sd_name / interface / inst_key
    Special virtual interfaces:
      _device_ / Tools / {iface_lower}  →  …/_Tools/{iface_lower}/Photo/
      {sd_key} / _photos_ / {type}      →  …/{sd_dir}/_Photos/{type}/Photo/
    """
    project_dir = Path(os.path.dirname(os.path.abspath(yaml_path)))
    short  = (yaml_data.get('client_short') or 'proj').strip().replace(' ', '_').upper()
    device = (yaml_data.get('device') or 'device').strip().replace(' ', '_').replace('/', '-')

    # ── Device-level tool photos ──────────────────────────────────────────────
    if sd_key == '_device_' and interface == 'Tools':
        inst_dir    = project_dir / short / device / '_Tools' / inst_key
        file_prefix = f'{short}_{device}_tools_{inst_key}'
        target_dir  = inst_dir / 'Photo'
        return target_dir, file_prefix

    # ── Subdevice-level photos ────────────────────────────────────────────────
    if interface == '_photos_':
        # Resolve sd_name from virtual instances list (fastest) or fall back
        sd_name = ''
        for virt in collect_subdevice_photos(yaml_data):
            if virt['sd_key'] == sd_key:
                sd_name = virt['sd_name']
                break
        sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-') if sd_name else sd_key
        inst_dir    = project_dir / short / device / sd_dir / '_Photos' / inst_key
        file_prefix = f'{short}_{device}_{sd_dir}_photos_{inst_key}'
        target_dir  = inst_dir / 'Photo'
        return target_dir, file_prefix

    # Resolve sd_name from subdevices — handles both list and dict formats
    raw_subdevices = yaml_data.get('subdevices')
    sd_name = ''
    if isinstance(raw_subdevices, list):
        for sd in raw_subdevices:
            if not isinstance(sd, dict):
                continue
            # Direct name match
            name = sd.get('name', '')
            name_key = name.lower().replace(' ', '_')
            if name_key == sd_key:
                sd_name = name
                break
            # Component-key match (central_unit, hand_unit, etc.)
            known_ifaces = set(INTERFACE_MODULES.keys())
            for comp_key, comp_val in sd.items():
                if comp_key in ('name', 'id', 'description'):
                    continue
                if isinstance(comp_val, dict):
                    if any(k in known_ifaces for k in comp_val):
                        if comp_key.lower().replace(' ', '_') == sd_key:
                            sd_name = comp_key.replace('_', ' ').title()
                            break
            if sd_name:
                break
    elif isinstance(raw_subdevices, dict):
        sd_body = raw_subdevices.get(sd_key, {})
        sd_name = sd_body.get('name', sd_key) if isinstance(sd_body, dict) else sd_key

    # Clean sd_name for filesystem use
    sd_dir = sd_name.strip().replace(' ', '_').replace('/', '-') if sd_name else ''

    if sd_dir:
        inst_dir    = project_dir / short / device / sd_dir / interface / inst_key
        file_prefix = f"{short}_{device}_{sd_dir}_{interface}_{inst_key}"
    else:
        inst_dir    = project_dir / short / device / interface / inst_key
        file_prefix = f"{short}_{device}_{interface}_{inst_key}"

    evidence_entries = _mod_evidence(module)
    subdir = evidence_entries[0]['subdir'] if evidence_entries else ''
    target_dir = inst_dir / subdir if subdir else inst_dir
    return target_dir, file_prefix


@app.route('/api/check_evidence', methods=['POST'])
def check_evidence():
    """
    Check whether evidence already exists for a module before uploading.
    Returns {exists: bool, existing_files: [...], accepted_patterns: [...]}
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '')
    sd_key     = data.get('sd_key', '')
    interface  = data.get('interface', '')
    inst_key   = data.get('inst_key', '')
    module     = data.get('module', '')
    filename   = data.get('filename', '')

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        yaml_data = load_yaml(pinfo['yaml_path'])
        target_dir, _ = _module_target_dir(
            yaml_data, pinfo['yaml_path'], sd_key, interface, inst_key, module)

        evidence_entries = _mod_evidence(module)
        patterns = []
        for e in evidence_entries:
            patterns.extend(e.get('patterns', []))

        existing = []
        if target_dir.exists():
            import fnmatch as _fnmatch
            for f in sorted(target_dir.iterdir()):
                if f.is_file() and any(_fnmatch.fnmatch(f.name, p) for p in patterns):
                    existing.append({'name': f.name, 'size': f.stat().st_size,
                                     'mtime': f.stat().st_mtime})

        # Validate the incoming filename against accepted patterns
        import fnmatch as _fn
        valid_type = any(_fn.fnmatch(filename, p) for p in patterns) if patterns and filename else True

        return jsonify({
            'exists':           bool(existing),
            'existing_files':   existing,
            'accepted_patterns': patterns,
            'valid_type':        valid_type,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _mark_photo_module_complete(yaml_path: str, project_id: str,
                               sd_key: str, interface: str, inst_key: str,
                               module: str) -> None:
    """Mark a photo module as complete in progress.json and emit module_status."""
    try:
        _prog    = load_progress(yaml_path)
        _ms      = _prog.setdefault('module_status', {})
        _iid     = f"{sd_key}.{interface}.{inst_key}"
        _mod_key = f"{_iid}.{module}"
        _ms[_mod_key] = {
            'status':    'complete',
            'detail':    'Photo uploaded',
            'timestamp': datetime.now().isoformat(),
        }
        # Photo instances are single-module — if the module is complete the
        # instance is complete too.  Add iid to completed_instances so that
        # compute_progress() marks the instance as completed.
        _ci = _prog.setdefault('completed_instances', [])
        if _iid not in _ci:
            _ci.append(_iid)
        _progress_file = Path(os.path.dirname(os.path.abspath(yaml_path))) / 'progress.json'
        with open(str(_progress_file), 'w', encoding='utf-8') as _pf:
            json.dump(_prog, _pf, indent=2)
        socketio.emit('module_status', {
            'subdevice': sd_key,
            'interface': interface,
            'instance':  inst_key,
            'module':    module,
            'status':    'complete',
            'detail':    'Photo uploaded',
        }, room=_room(project_id))
    except Exception as _e:
        app.logger.warning(f"Could not mark photo module complete: {_e}")


@app.route('/api/upload_evidence', methods=['POST'])
def upload_evidence():
    """
    Upload an evidence file for a specific module.
    If a file already exists it is archived to project_dir/deleted/ before saving.
    The uploaded file is renamed to match the module's naming schema.
    """
    project_id = request.form.get('project_id', '').strip()
    sd_key     = request.form.get('sd_key', '').strip()
    interface  = request.form.get('interface', '').strip()
    inst_key   = request.form.get('inst_key', '').strip()
    module     = request.form.get('module', '').strip()
    replace    = request.form.get('replace', 'false').strip().lower() == 'true'

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    upload = request.files['file']
    orig_filename = upload.filename or ''

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        pid_clean = project_id.strip().lower()
        for k, v in raw.get('projects', {}).items():
            if k.strip().lower() == pid_clean:
                pinfo      = v
                project_id = k
                break
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        yaml_data = load_yaml(pinfo['yaml_path'])
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        target_dir, file_prefix = _module_target_dir(
            yaml_data, pinfo['yaml_path'], sd_key, interface, inst_key, module)

        evidence_entries = _mod_evidence(module)
        patterns = []
        for e in evidence_entries:
            patterns.extend(e.get('patterns', []))

        # ── Validate file type ─────────────────────────────────────────────
        import fnmatch as _fn
        ext = orig_filename.rsplit('.', 1)[-1].lower() if '.' in orig_filename else ''
        # For content-type fallback (iOS/empty filename)
        if not ext:
            ct = (upload.content_type or '').lower()
            ext = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif',
                   'image/webp': 'webp', 'text/plain': 'txt',
                   'application/octet-stream': 'pcap'}.get(ct, '')
        if patterns and not any(_fn.fnmatch(f'file.{ext}', p) for p in patterns):
            # Try matching raw filename too
            if orig_filename and not any(_fn.fnmatch(orig_filename, p) for p in patterns):
                return jsonify({
                    'error': f"File type '.{ext}' is not valid for {module}. "
                             f"Expected: {', '.join(sorted(set(patterns)))}"
                }), 400

        # ── Build canonical filename for this module ───────────────────────
        mod_lower = module.lower().replace('_', '')
        target_dir.mkdir(parents=True, exist_ok=True)

        # ── Photo module (and PHOTO-* device/subdevice photos): incremental naming ──
        if _is_photo_module(module):
            # Find the next available index
            import re as _re
            existing_indices = []
            for f in target_dir.iterdir() if target_dir.exists() else []:
                if not f.is_file():
                    continue
                # Match: prefix_photo.ext  OR  prefix_photo_N.ext
                m = _re.match(
                    rf'^{_re.escape(file_prefix)}_photo(?:_(\d+))?\.({ext})$',
                    f.name, _re.IGNORECASE)
                if m:
                    idx = int(m.group(1)) if m.group(1) else 0
                    existing_indices.append(idx)

            if existing_indices:
                next_idx   = max(existing_indices) + 1
                canon_name = f"{file_prefix}_photo_{next_idx}.{ext}"
            else:
                canon_name = f"{file_prefix}_photo.{ext}"

            dest = target_dir / canon_name
            upload.save(str(dest))
            _mark_photo_module_complete(
                pinfo['yaml_path'], project_id, sd_key, interface, inst_key, module)
            return jsonify({
                'success':  True,
                'saved_as': canon_name,
                'path':     str(dest.relative_to(project_dir)),
                'archived': None,
            })

        # ── All other modules: canonical name, archive if replacing ───────
        canon_name = f"{file_prefix}_{module.lower()}.{ext}"
        _canon_map = {
            'NmapLive':         f"{file_prefix}_nmap_live.{ext}",
            'NmapPort':         f"{file_prefix}_nmap_port.{ext}",
            'ConfigDiscovery':  f"{file_prefix}_config_discovery.{ext}",
            'BannerGrab':       f"{file_prefix}_banner.{ext}",
            'Tcpdump_running':  f"{file_prefix}_tcpdump_running.{ext}",
            'Tcpdump_boot':     f"{file_prefix}_tcpdump_boot.{ext}",
            'Tcpdump_shutdown': f"{file_prefix}_tcpdump_shutdown.{ext}",
        }
        canon_name = _canon_map.get(module, canon_name)

        dest = target_dir / canon_name

        # Archive existing file if present and user confirmed replace
        archived = None
        if dest.exists():
            if not replace:
                return jsonify({'error': 'File already exists', 'exists': True}), 409
            ts          = datetime.now().strftime('%Y%m%d_%H%M%S')
            deleted_dir = project_dir / 'deleted'
            deleted_dir.mkdir(exist_ok=True)
            archive_name = f"{dest.stem}__{ts}{dest.suffix}"
            archive_path = deleted_dir / archive_name
            shutil.move(str(dest), str(archive_path))
            archived = str(archive_path.relative_to(project_dir))

        # Archive any other matching files in target_dir if replacing
        if replace and target_dir.exists() and patterns:
            for existing_f in list(target_dir.iterdir()):
                if existing_f.is_file() and existing_f != dest:
                    if any(_fn.fnmatch(existing_f.name, p) for p in patterns):
                        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                        deleted_dir = project_dir / 'deleted'
                        deleted_dir.mkdir(exist_ok=True)
                        shutil.move(str(existing_f),
                                    str(deleted_dir / f"{existing_f.stem}__{ts}{existing_f.suffix}"))

        # ── Content validation before saving ─────────────────────────────
        # Read the uploaded file into a temp location first, validate,
        # then move to final destination.
        import tempfile as _tmp
        with _tmp.NamedTemporaryFile(delete=False, suffix=file_path.suffix if 'file_path' in dir() else f'.{ext}') as _tf:
            _tmp_path = Path(_tf.name)
        upload.save(str(_tmp_path))

        valid, val_msg = _validate_upload_content(module, _tmp_path)
        if not valid:
            _tmp_path.unlink(missing_ok=True)
            return jsonify({'error': val_msg}), 422

        # Move validated file to final destination
        import shutil as _sh
        _sh.move(str(_tmp_path), str(dest))

        # Trigger background parsing of the uploaded file to extract findings.
        # We run this in a daemon thread so the HTTP response returns immediately.
        def _parse_uploaded_evidence(module_name, file_path, yaml_path, proj_id):
            try:
                import threading as _th
                _run_upload_parser(module_name, Path(file_path), yaml_path, proj_id)
            except Exception as _e:
                app.logger.warning(f"Upload parse error for {module_name}: {_e}")

        import threading as _t
        _t.Thread(
            target=_parse_uploaded_evidence,
            args=(module, str(dest), pinfo['yaml_path'], project_id),
            daemon=True,
        ).start()

        return jsonify({
            'success':  True,
            'saved_as': canon_name,
            'path':     str(dest.relative_to(project_dir)),
            'archived': archived,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/list_deleted/<project_id>')
def list_deleted(project_id):
    """List all files in the project's deleted/ archive folder."""
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    try:
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        deleted_dir = project_dir / 'deleted'
        items = []
        if deleted_dir.exists():
            for f in sorted(deleted_dir.rglob('*'), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file():
                    stat = f.stat()
                    # Try to reconstruct original name (strip __YYYYMMDD_HHMMSS suffix)
                    stem = f.stem
                    import re as _re
                    m = _re.match(r'^(.+)__(\d{8}_\d{6})$', stem)
                    original_stem = m.group(1) if m else stem
                    archived_at   = m.group(2) if m else ''
                    items.append({
                        'name':          f.name,
                        'original_name': original_stem + f.suffix,
                        'archived_at':   archived_at,
                        'size':          stat.st_size,
                        'mtime':         stat.st_mtime,
                        'deleted_path':  str(f.relative_to(project_dir)),
                    })
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/view_deleted_file', methods=['POST'])
def view_deleted_file():
    """Return content of a file from the deleted/ archive for browser viewing."""
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '').strip()
    rel_path   = data.get('rel_path', '').strip()
    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404
    try:
        import base64 as _b64, fnmatch as _fn
        project_dir = Path(os.path.dirname(pinfo['yaml_path']))
        target = project_dir / rel_path
        # Safety: must stay inside project_dir
        target = target.resolve()
        if not str(target).startswith(str(project_dir.resolve())):
            return jsonify({'error': 'Access denied'}), 403
        if not target.is_file():
            return jsonify({'error': 'File not found'}), 404
        ext  = target.suffix.lower().lstrip('.')
        size = target.stat().st_size
        IMAGE_EXTS = {'jpg','jpeg','png','gif','webp','bmp','svg'}
        MIME_MAP   = {'jpg':'image/jpeg','jpeg':'image/jpeg','png':'image/png',
                      'gif':'image/gif','webp':'image/webp','bmp':'image/bmp',
                      'svg':'image/svg+xml'}
        if ext in IMAGE_EXTS:
            with open(target, 'rb') as fh:
                raw_bytes = fh.read()
            mime = MIME_MAP.get(ext, 'image/jpeg')
            return jsonify({'type':'image','filename':target.name,'size':size,
                            'data_uri':f'data:{mime};base64,{_b64.b64encode(raw_bytes).decode()}'})
        else:
            MAX = 512 * 1024
            with open(target, 'rb') as fh:
                raw_bytes = fh.read(MAX)
            truncated = target.stat().st_size > MAX
            return jsonify({'type':'text','filename':target.name,'size':size,
                            'content':raw_bytes.decode('utf-8', errors='replace'),
                            'truncated':truncated})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/set_photo_context', methods=['POST'])
def set_photo_context():
    """
    Called by the Evidence tab when the user chooses 'Take photo with mobile'.
    Stores the instance context so that the mobile join page can direct its
    upload to the correct module directory.
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '')
    if not project_id:
        return jsonify({'error': 'project_id required'}), 400
    _photo_context[project_id] = {
        'sd_key':    data.get('sd_key', ''),
        'interface': data.get('interface', ''),
        'inst_key':  data.get('inst_key', ''),
        'module':    data.get('module', 'Photo'),
        'instance_id': f"{data.get('sd_key','')}.{data.get('interface','')}.{data.get('inst_key','')}",
    }
    # Also broadcast to the room so join.html gets it immediately via socket
    socketio.emit('photo_context', _photo_context[project_id], room=_room(project_id))
    return jsonify({'ok': True})


@app.route('/api/get_photo_context/<project_id>')
def get_photo_context(project_id):
    """Return the current photo context for a project (polled by join.html on load)."""
    ctx = _photo_context.get(project_id)
    if ctx:
        return jsonify(ctx)
    return jsonify({}), 200


@app.route('/api/scan_evidence', methods=['POST'])
def scan_evidence():
    """
    Scan all modules for a given instance and return which ones have evidence.
    Returns a dict keyed by module name: {exists, files: [{name, size}]}
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '')
    sd_key     = data.get('sd_key', '')
    interface  = data.get('interface', '')
    inst_key   = data.get('inst_key', '')
    modules    = data.get('modules', [])

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        import fnmatch as _fn
        yaml_data = load_yaml(pinfo['yaml_path'])
        result = {}
        for mod in modules:
            target_dir, _ = _module_target_dir(
                yaml_data, pinfo['yaml_path'], sd_key, interface, inst_key, mod)
            evidence_entries = _mod_evidence(mod)
            files = []
            for ev in evidence_entries:
                sub   = ev.get('subdir', '')
                pats  = ev.get('patterns', [])
                photo = ev.get('photo_only', False)
                sd_path = (target_dir.parent / sub) if sub else target_dir
                if not sd_path.exists():
                    continue
                # For nested subdirs (e.g. Web/screenshots) use rglob
                iter_fn = sd_path.rglob('*') if '/' in sub else sd_path.iterdir()
                for f in sorted(iter_fn):
                    try:
                        if not f.is_file():
                            continue
                        if pats and not any(_fn.fnmatch(f.name, p) for p in pats):
                            continue
                        rel_name = str(f.relative_to(target_dir.parent))
                        files.append({
                            'name':  rel_name,
                            'size':  f.stat().st_size,
                            'image': photo or f.suffix.lower().lstrip('.') in
                                     ('jpg','jpeg','png','gif','webp'),
                        })
                    except Exception:
                        continue
            result[mod] = {'exists': bool(files), 'files': files}
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/view_evidence', methods=['POST'])
def view_evidence():
    """
    Return the content of an evidence file for in-browser viewing.
    Images are returned as base64 data URIs.
    Text/binary files are returned as UTF-8 text (decoded lossy).
    """
    data       = request.get_json(force=True) or {}
    project_id = data.get('project_id', '')
    sd_key     = data.get('sd_key', '')
    interface  = data.get('interface', '')
    inst_key   = data.get('inst_key', '')
    module     = data.get('module', '')
    filename   = data.get('filename', '')   # specific file; empty = first match

    raw   = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Project not found'}), 404

    try:
        import fnmatch as _fn, base64 as _b64
        yaml_data = load_yaml(pinfo['yaml_path'])
        target_dir, _ = _module_target_dir(
            yaml_data, pinfo['yaml_path'], sd_key, interface, inst_key, module)

        evidence_entries = _mod_evidence(module)
        patterns = [p for e in evidence_entries for p in e.get('patterns', [])]

        # Find the target file — search all MODULE_EVIDENCE subdirs for module
        # inst_dir = parent of the primary target_dir
        inst_dir = target_dir.parent
        target_file: Path | None = None
        if filename:
            # filename may be a relative path like "Web/screenshots/foo.png"
            # Try inst_dir-relative first, then target_dir-relative
            for base in (inst_dir, target_dir):
                candidate = base / filename
                if candidate.is_file():
                    target_file = candidate
                    break
        if not target_file:
            # Auto-select: scan all MODULE_EVIDENCE subdirs in order
            for ev in _mod_evidence(module):
                sub  = ev.get('subdir', '')
                pats = ev.get('patterns', patterns)
                sd_path = (inst_dir / sub) if sub else inst_dir
                if not sd_path.exists():
                    continue
                scan = sorted(sd_path.rglob('*')) if '/' in sub else sorted(sd_path.iterdir())
                for f in scan:
                    if f.is_file() and (not pats or
                            any(_fn.fnmatch(f.name, p) for p in pats)):
                        target_file = f
                        break
                if target_file:
                    break

        if not target_file:
            return jsonify({'error': 'No evidence file found'}), 404

        ext  = target_file.suffix.lower().lstrip('.')
        size = target_file.stat().st_size

        IMAGE_EXTS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'}
        MIME_MAP   = {
            'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'png': 'image/png',  'gif': 'image/gif',
            'webp': 'image/webp','bmp': 'image/bmp',
            'svg': 'image/svg+xml',
        }

        if ext in IMAGE_EXTS:
            with open(target_file, 'rb') as fh:
                raw_bytes = fh.read()
            mime     = MIME_MAP.get(ext, 'image/jpeg')
            data_uri = f"data:{mime};base64,{_b64.b64encode(raw_bytes).decode()}"
            return jsonify({
                'type':     'image',
                'filename': target_file.name,
                'size':     size,
                'data_uri': data_uri,
                'mime':     mime,
            })
        else:
            if ext == 'pcap':
                return jsonify({
                    'type':      'text',
                    'filename':  target_file.name,
                    'size':      size,
                    'content':   _pcap_to_text(str(target_file)),
                    'truncated': False,
                })
            # Read as text, replacing undecodable bytes
            with open(target_file, 'rb') as fh:
                raw_bytes = fh.read()
            # Cap at 512 KB for display
            MAX = 512 * 1024
            truncated = len(raw_bytes) > MAX
            text = raw_bytes[:MAX].decode('utf-8', errors='replace')
            return jsonify({
                'type':      'text',
                'filename':  target_file.name,
                'size':      size,
                'content':   text,
                'truncated': truncated,
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── API: Module Status ─────────────────────────────────────────────────────────

@app.route('/api/module_status/<project_id>')
def api_module_status(project_id):
    """Return live module progress for a project."""
    raw = load_projects()
    pinfo = raw.get('projects', {}).get(project_id)
    if not pinfo:
        return jsonify({'error': 'Not found'}), 404
    try:
        yaml_data     = load_yaml(pinfo['yaml_path'])
        progress_data = load_progress(pinfo['yaml_path'])
        progress_map  = compute_progress(yaml_data, progress_data,
                                         active_project_id=project_id)
        completed, total = count_modules(yaml_data, progress_data)
        return jsonify({
            'progress_map': progress_map,
            'completed':    completed,
            'total':        total,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── SocketIO: Project Rooms + Gearbox Interaction ─────────────────────────────
#
# All clients viewing the same project share a Socket.IO room named
# "project:<project_id>".  The gearbox subprocess is keyed by project_id,
# not by the individual socket sid, so any member of the room can:
#   • see all console output, prompts, findings and status updates
#   • answer a prompt (e.g. a mobile device uploading a photo)
#   • kill the running process
#
# Mappings:
#   _active_procs   : project_id  -> Popen
#   _answer_queues  : project_id  -> Queue
#   _owner_sid      : project_id  -> sid of the socket that launched gearbox
#   _sid_to_project : sid         -> project_id  (for disconnect cleanup)
# ───────────────────────────────────────────────────────────────────────────────

_owner_sid:       dict[str, str]   = {}   # project_id -> launcher sid
_sid_to_project:  dict[str, str]   = {}   # sid        -> project_id
_pending_prompts: dict[str, dict]  = {}   # project_id -> last gearbox_prompt payload (or None)
_active_module:   dict[str, dict]  = {}   # project_id -> last module_status payload


def _room(project_id: str) -> str:
    """Return the Socket.IO room name for a project."""
    return f'project:{project_id}'


@socketio.on('connect')
def _on_connect():
    if not session.get('authenticated'):
        return False  # reject unauthenticated WebSocket connections


@socketio.on('disconnect')
def _on_disconnect():
    sid = request.sid
    project_id = _sid_to_project.pop(sid, None)
    if not project_id:
        return

    # If the disconnecting socket launched the current gearbox process,
    # leave the process running — other room members can still interact.
    # Only clean up if this was the *last* member tracking that project.
    if _owner_sid.get(project_id) == sid:
        # Check whether any other client is still in the room
        # (flask-socketio doesn't expose a member count directly, so we use
        # a conservative approach: clear the owner reference but keep the proc
        # alive so that a reconnect or another device can reclaim it)
        _owner_sid.pop(project_id, None)


@socketio.on('join_project')
def handle_join_project(data):
    """
    Every client emits this on page load. Puts the socket into the shared
    project room and sends back full console history so any tab/device
    catches up without losing output.
    """
    d          = data or {}
    project_id = d.get('project_id', '')
    if not project_id:
        return

    sid  = request.sid
    room = _room(project_id)
    join_room(room)
    _sid_to_project[sid] = project_id

    # Log the join in gauntlet log
    ua  = request.headers.get('User-Agent', '')
    ip  = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    entry = {
        'ts':    _ts(),
        'event': 'join',
        'sid':   sid,
        'ip':    ip,
        'ua':    ua,
        'tab':   d.get('tab', ''),
    }
    _buf_append(_gauntlet_log, project_id, entry)
    socketio.emit('gauntlet_log_entry', entry, room=room)

    running = project_id in _active_procs
    emit('session_state', {
        'project_id':      project_id,
        'gearbox_running': running,
        'pending_prompt':  _pending_prompts.get(project_id),
        'active_module':   _active_module.get(project_id),
        'members':         'joined',
        'console_history': _console_buffer.get(project_id, []),
        'gearbox_log':     _gearbox_log.get(project_id, []),
    })

    socketio.emit('peer_joined', {
        'project_id': project_id,
        'message':    'A new device has joined the project session.',
    }, room=room, include_self=False)


@socketio.on('leave_project')
def handle_leave_project(data):
    project_id = (data or {}).get('project_id', '')
    if project_id:
        leave_room(_room(project_id))
        _sid_to_project.pop(request.sid, None)


@socketio.on('start_gearbox')
def handle_start_gearbox(data):
    d = data or {}
    project_id   = d.get('project_id', '')
    gearbox_path = d.get('gearbox_path', '').strip() or 'gearbox.py'
    yaml_path    = d.get('yaml_path', '')
    # Resolve a bare/relative path to the canonical install location
    if not os.path.isabs(gearbox_path) or not os.path.isfile(gearbox_path):
        _default = os.path.normpath(os.path.join(_BASE_DIR, '..', 'Gearbox', 'gearbox.py'))
        if os.path.isfile(_default):
            gearbox_path = _default
    extra_args   = d.get('extra_args', [])

    if not project_id:
        emit('gearbox_error', {'error': 'project_id is required to start gearbox.'})
        return

    room = _room(project_id)

    # Prevent launching a second instance if one is already running
    if project_id in _active_procs:
        emit('gearbox_error', {
            'error': 'Gearbox is already running for this project on another device.'})
        return

    _kill_project_process(project_id)   # clean up any stale state

    # Clear per-project buffers for the new run
    _console_buffer[project_id] = []
    _gearbox_log[project_id]    = []
    _observations[project_id]   = []
    _error_buffer[project_id]   = []

    answer_q: queue.Queue = queue.Queue()
    _answer_queues[project_id] = answer_q
    _owner_sid[project_id]     = request.sid

    cmd = ['sudo', '-E', 'python3', gearbox_path]
    if yaml_path:
        cmd.append(yaml_path)

    # Pass all network interfaces to gearbox so photo prompts show a per-interface QR
    flask_port  = app.config.get('SERVER_PORT', 5000)
    ifaces      = get_all_interfaces()
    iface_list  = [
        {'name': i['name'], 'ip': i['ip'],
         'url': f"https://{i['ip']}:{flask_port}/join/{project_id}"}
        for i in ifaces
    ]
    cmd.extend(['--join-interfaces', json.dumps(iface_list)])

    # Tell gearbox to write all output into the user-designated project folder
    project_output_dir = os.path.dirname(os.path.abspath(yaml_path)) if yaml_path else ''
    if project_output_dir:
        cmd.extend(['--project-dir', project_output_dir])

    # Pass Nessus credentials as CLI arguments so they survive the sudo boundary.
    # Gearbox will load from config.yaml directly; these args override that if set.
    nessus_user_val = ''
    for user_key in ('nessus_user', 'NESSUS_USER', 'NESSUS_USERNAME'):
        nessus_user_val = os.environ.get(user_key, '').strip()
        if nessus_user_val:
            break
    if nessus_user_val:
        cmd.extend(['--nessus-user', nessus_user_val])

    nessus_pass_val = ''
    for pass_key in ('nessus_pass', 'NESSUS_PASS', 'nessus_password', 'NESSUS_PASSWORD'):
        nessus_pass_val = os.environ.get(pass_key, '').strip()
        if nessus_pass_val:
            break
    if nessus_pass_val:
        cmd.extend(['--nessus-pass', nessus_pass_val])

    cmd.extend(extra_args)

    proc_env = dict(os.environ)

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
            env=proc_env,
        )
    except FileNotFoundError:
        emit('gearbox_error', {'error': f'File not found: {gearbox_path}'})
        _answer_queues.pop(project_id, None)
        _owner_sid.pop(project_id, None)
        return
    except Exception as e:
        emit('gearbox_error', {'error': str(e)})
        _answer_queues.pop(project_id, None)
        _owner_sid.pop(project_id, None)
        return

    _active_procs[project_id] = proc

    # Broadcast to the whole room so every connected device knows gearbox started
    socketio.emit('gearbox_started', {'pid': proc.pid}, room=room)

    threading.Thread(
        target=_stdout_reader, args=(proc, project_id, answer_q),
        daemon=True).start()
    threading.Thread(
        target=_stderr_reader, args=(proc, project_id),
        daemon=True).start()


def _stdout_reader(proc: subprocess.Popen, project_id: str, answer_q: queue.Queue):
    """
    Stream gearbox stdout to the project room and buffer for late-joiners.
    Structured protocol markers are parsed and emitted as typed events.
    Every line is also timestamped and buffered in _console_buffer.
    Gearbox log lines ([INFO]/[WARNING]/[ERROR]) go to _gearbox_log too.
    """
    GB_PROMPT  = '__GB_PROMPT__:'
    GB_STATUS  = '__GB_STATUS__:'
    GB_FINDING = '__GB_FINDING__:'
    GB_LOG     = '__GB_LOG__:'

    room = _room(project_id)

    def _emit_console(text: str, stream: str = 'stdout'):
        ts  = _ts()
        msg = {'text': text, 'stream': stream, 'ts': ts}
        _buf_append(_console_buffer, project_id, msg)
        socketio.emit('gearbox_output', msg, room=room)

    def _emit_gblog(level: str, message: str):
        ts    = _ts()
        entry = {'ts': ts, 'level': level, 'message': message}
        _buf_append(_gearbox_log, project_id, entry)
        socketio.emit('gearbox_log_entry', entry, room=room)

    def _emit_error(error_type: str, source: str, message: str, detail: str = '',
                    category: str = ''):
        ts    = _ts()
        # Auto-classify if no category supplied
        if not category:
            _msg_l = (message + ' ' + detail).lower()
            if any(k in _msg_l for k in (
                    'connection', 'socket', 'timeout', 'refused', 'unreachable',
                    'no route', 'network', 'timed out', 'reset by peer',
                    'broken pipe', 'eof', 'ssl handshake', 'dns')):
                category = 'Communication'
            elif any(k in _msg_l for k in (
                    'tool', 'stderr', 'exit code', 'non-zero', 'crashed',
                    'segfault', 'killed', 'command not found', 'returncode',
                    'failed to run', 'process', 'binary', 'permission denied')):
                category = 'Tool'
            else:
                category = 'Gearbox'
        entry = {
            'ts':       ts,
            'type':     error_type,
            'source':   source,
            'message':  message,
            'detail':   detail,
            'category': category,
        }
        _buf_append(_error_buffer, project_id, entry)
        socketio.emit('error_entry', entry, room=room)

    try:
        for raw_line in proc.stdout:
            line = raw_line.rstrip('\n')

            if line.startswith(GB_PROMPT):
                try:
                    payload = json.loads(line[len(GB_PROMPT):])
                    _pending_prompts[project_id] = payload
                    socketio.emit('gearbox_prompt', payload, room=room)
                    _emit_gblog('PROMPT', payload.get('question', '')[:120])
                    try:
                        answer = answer_q.get(timeout=1800)
                        _pending_prompts.pop(project_id, None)
                        proc.stdin.write(answer + '\n')
                        proc.stdin.flush()
                        _emit_gblog('ANSWER', '< [password hidden]' if payload.get('type') == 'password' else f'< {answer[:80]}')
                    except queue.Empty:
                        _pending_prompts.pop(project_id, None)
                        socketio.emit('prompt_resolved', {}, room=room)
                        socketio.emit('gearbox_error',
                                      {'error': 'Prompt timed out (30 min).'}, room=room)
                        break
                except Exception:
                    _emit_console(line)

            elif line.startswith(GB_STATUS):
                try:
                    payload = json.loads(line[len(GB_STATUS):])
                    _active_module[project_id] = payload
                    socketio.emit('module_status', payload, room=room)
                    status_str = (
                        f"[{payload.get('interface')}/{payload.get('instance')}] "
                        f"{payload.get('module')}: {payload.get('status','').upper()}"
                        + (f" — {payload.get('detail')}" if payload.get('detail') else '')
                    )
                    _emit_console(status_str, 'status')
                    _emit_gblog(payload.get('status','STATUS').upper(), status_str)
                    # Dynamic evidence update
                    socketio.emit('evidence_update', payload, room=room)
                except Exception:
                    _emit_console(line)

            elif line.startswith(GB_FINDING):
                try:
                    finding = json.loads(line[len(GB_FINDING):])
                    socketio.emit('new_finding', finding, room=room)
                    finding_str = f"[FINDING][{finding.get('risk','')}] {finding.get('title','')}"
                    _emit_console(finding_str, 'finding')
                    _emit_gblog('FINDING', finding_str)
                    # Store as observation
                    obs = {
                        'ts':      _ts(),
                        'title':   finding.get('title', ''),
                        'desc':    finding.get('description', ''),
                        'tool':    ', '.join(finding.get('tools_used', [])),
                        'version': '',
                        'file':    '',
                        'output':  str(finding.get('commands_used', [])),
                        'risk':    finding.get('risk', ''),
                        'type':    'finding',
                    }
                    _buf_append(_observations, project_id, obs)
                    socketio.emit('observation_entry', obs, room=room)
                except Exception:
                    _emit_console(line)

            elif line.startswith(GB_LOG):
                raw_msg = line[len(GB_LOG):]
                _emit_console(raw_msg)
                import re as _re
                m = _re.match(r'^\[([A-Z]+)\]\s*(.*)', raw_msg, _re.DOTALL)
                level   = m.group(1) if m else 'INFO'
                message = m.group(2) if m else raw_msg
                _emit_gblog(level, message)
                # Pipe errors and warnings into the error buffer
                if level in ('ERROR', 'WARNING', 'WARN', 'FATAL'):
                    # Extract source from [context/context] prefix if present
                    src_m  = _re.match(r'^\[([^\]]+)\](.*)$', message)
                    source = src_m.group(1).strip() if src_m else 'gearbox'
                    body   = src_m.group(2).strip() if src_m else message
                    _emit_error(level, source, body)

            elif line.startswith('__GB_OBSERVATION__:'):
                try:
                    obs = json.loads(line[len('__GB_OBSERVATION__:'):])
                    obs.setdefault('ts', _ts())
                    obs.setdefault('type', 'observation')
                    _buf_append(_observations, project_id, obs)
                    socketio.emit('observation_entry', obs, room=room)
                    _emit_gblog('OBS', f"[{obs.get('tool','')}] {obs.get('title','')}")
                except Exception:
                    _emit_console(line)

            else:
                _emit_console(line)

    except Exception as e:
        socketio.emit('gearbox_error', {'error': f'Read error: {e}'}, room=room)

    ret = proc.wait()
    _emit_gblog('DONE', f'Gearbox exited with code {ret}')
    socketio.emit('gearbox_done', {'returncode': ret}, room=room)
    _active_procs.pop(project_id, None)
    _answer_queues.pop(project_id, None)
    _owner_sid.pop(project_id, None)
    _pending_prompts.pop(project_id, None)
    _active_module.pop(project_id, None)

    # Mark project complete if all instances finished
    try:
        _projs = load_projects()
        _pinfo = _projs.get("projects", {}).get(project_id)
        if _pinfo:
            _yaml_path = _pinfo.get("yaml_path", "")
            if _yaml_path and os.path.exists(_yaml_path):
                _yaml_data = load_yaml(_yaml_path)
                _progress  = load_progress(_yaml_path)
                _pm        = compute_progress(_yaml_data, _progress)
                if _pm and all(v.get("completed") for v in _pm.values()):
                    _pinfo["status"] = "complete"
                    save_projects(_projs)
                    socketio.emit('project_status_update',
                                  {'project_id': project_id, 'status': 'complete'}, room=room)
    except Exception:
        pass

    threading.Thread(target=_dequeue_next, daemon=True).start()


def _stderr_reader(proc: subprocess.Popen, project_id: str):
    room = _room(project_id)

    def _emit_console(text: str, stream: str = 'stderr'):
        ts  = _ts()
        msg = {'text': text, 'stream': stream, 'ts': ts}
        _buf_append(_console_buffer, project_id, msg)
        socketio.emit('gearbox_output', msg, room=room)

    def _emit_err(text: str):
        entry = {'ts': _ts(), 'type': 'STDERR', 'source': 'gearbox',
                 'message': text, 'detail': ''}
        _buf_append(_error_buffer, project_id, entry)
        socketio.emit('error_entry', entry, room=room)

    try:
        for line in proc.stderr:
            text = line.rstrip('\n')
            _emit_console(text, 'stderr')
            if text.strip():
                _emit_err(text)
    except Exception:
        pass


@socketio.on('gearbox_answer')
def handle_gearbox_answer(data):
    """
    Any device in the project room can answer a prompt.
    The answer is routed to the queue for that project's running gearbox process.
    """
    d          = data or {}
    project_id = d.get('project_id', '')
    answer     = d.get('answer', '')

    if not project_id:
        # Fallback: try to look up the project from the sender's sid
        project_id = _sid_to_project.get(request.sid, '')

    q = _answer_queues.get(project_id)
    if q:
        q.put(answer)
        # Mask passwords in the console echo — check if the pending prompt was a password type
        pending = _pending_prompts.get(project_id) or {}
        ptype   = pending.get('type', 'text')
        pqtext  = pending.get('question', '')
        is_pw   = (ptype == 'password' or
                   bool(re.search(r'password|passphrase|secret|credential', pqtext, re.I)))
        echo_text = '< [password hidden]' if is_pw else f'< {answer}'
        socketio.emit('gearbox_output', {
            'text': echo_text,
            'stream': 'system',
        }, room=_room(project_id))
        # Tell every client in the room (including mobile) to dismiss the prompt UI
        _pending_prompts.pop(project_id, None)
        socketio.emit('prompt_resolved', {}, room=_room(project_id))
    # If no queue exists the answer is silently ignored — this is expected
    # when a photo is uploaded from the Evidence tab with no gearbox running.


@socketio.on('kill_gearbox')
def handle_kill_gearbox(data):
    project_id = (data or {}).get('project_id', '') or \
                 _sid_to_project.get(request.sid, '')
    if project_id:
        _kill_project_process(project_id)
        socketio.emit('gearbox_stopped', {}, room=_room(project_id))
    else:
        emit('gearbox_stopped', {})


def _kill_project_process(project_id: str):
    """
    Safely terminate the gearbox subprocess for a project.

    Sends SIGTERM to the full process tree (sudo + gearbox + children) so
    gearbox's _sighandler fires and _ethernet_shutdown_cleanup() runs
    (kills Responder, stops Nessus scans, reverts DHCP interface).
    A background thread force-kills with SIGKILL after 8 s if the process
    is still alive.
    """
    import signal as _sig
    import threading as _threading
    import time as _time

    # Unblock any pending prompt so the stdout-reader isn't stuck waiting
    q = _answer_queues.get(project_id)
    if q:
        try:
            q.put_nowait('\n')
        except Exception:
            pass

    proc = _active_procs.pop(project_id, None)
    if proc:
        # Collect the full process tree: sudo → python3 → gearbox children
        pids_to_signal = []
        try:
            import psutil as _ps
            root = _ps.Process(proc.pid)
            pids_to_signal = [p.pid for p in [root] + root.children(recursive=True)]
        except Exception:
            pids_to_signal = [proc.pid]

        # SIGTERM — triggers gearbox _sighandler → _ethernet_shutdown_cleanup
        for pid in pids_to_signal:
            try:
                os.kill(pid, _sig.SIGTERM)
            except Exception:
                pass

        # SIGKILL fallback after 8 s
        def _force_kill(pids, p):
            _time.sleep(8)
            for pid in pids:
                try:
                    os.kill(pid, _sig.SIGKILL)
                except Exception:
                    pass
            try:
                p.kill()
            except Exception:
                pass

        _threading.Thread(target=_force_kill, args=(pids_to_signal, proc),
                          daemon=True).start()

    _answer_queues.pop(project_id, None)
    _owner_sid.pop(project_id, None)
    _pending_prompts.pop(project_id, None)
    _active_module.pop(project_id, None)


# ─── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not _auth.validate_csrf(request.form.get('csrf_token')):
            _uname = request.form.get('username', '').strip()
            return render_template('login.html',
                                   error='Session expired \u2014 please log in again.',
                                   username=_uname,
                                   csrf_token=_auth.generate_csrf())
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if _auth.verify_credentials(username, password):
            session.permanent = True
            session['authenticated'] = True
            session['username'] = username
            if _auth.must_change_password():
                return redirect(url_for('change_password'))
            next_url = request.form.get('next', '').strip()
            if next_url and next_url.startswith('/') and '://' not in next_url:
                return redirect(next_url)
            return redirect(url_for('index'))
        next_url = request.form.get('next', '')
        return render_template('login.html', error='Invalid credentials.', username=username,
                               csrf_token=_auth.generate_csrf(), next_url=next_url)
    next_url = request.args.get('next', '')
    return render_template('login.html', csrf_token=_auth.generate_csrf(), next_url=next_url)


@app.route('/logout')
def logout():
    session.clear()
    import time as _t
    return redirect(url_for('login', _t=int(_t.time())))


@app.route('/api/session_ping', methods=['POST'])
def session_ping():
    if not session.get('authenticated'):
        return jsonify({'ok': False}), 401
    session.modified = True
    return jsonify({'ok': True})


@app.route('/api/nexus-status')
def nexus_status():
    """Unauthenticated status probe for the Nexus hub."""
    return jsonify({"app": "gauntlet", "tool": "gauntlet", "hostname": socket.gethostname(), "scanning": bool(_active_procs), "version": VERSION})


@app.route('/api/arbiter-projects')
def api_arbiter_projects():
    """Return Gauntlet/Gearbox projects as normalized project records for Arbiter."""
    raw = load_projects()
    result = []
    for pid, proj in raw.get("projects", {}).items():
        # Derive client_name from yaml_path: …/clients/<client_short>/<year>/gearbox/…
        yaml_path = proj.get("yaml_path", "")
        client_name = proj.get("name", pid)
        project_dir = ""
        if yaml_path:
            try:
                p = Path(yaml_path)
                project_dir = str(p.parent)
                parts = p.parts
                clients_idx = next((i for i, x in enumerate(parts) if x == "clients"), None)
                if clients_idx is not None and clients_idx + 1 < len(parts):
                    client_name = parts[clients_idx + 1]
            except Exception:
                pass
        # Read full engagement metadata from the YAML
        _client_short = _consultant = _consultant_email = ""
        _poc_name = _poc_email = _poc_phone = ""
        _start = _end = ""
        try:
            if yaml_path and os.path.exists(yaml_path):
                _y = load_yaml(yaml_path)
                if isinstance(_y, dict):
                    _client_short     = str(_y.get("client_short", "") or "")
                    _consultant       = str(_y.get("consultant_name", "") or "")
                    _consultant_email = str(_y.get("consultant_email", "") or "")
                    _start            = str(_y.get("start_date", "") or "")
                    _end              = str(_y.get("end_date", "") or "")
                    _poc              = _y.get("client_poc", {})
                    if isinstance(_poc, dict):
                        _poc_name  = str(_poc.get("name",  "") or "")
                        _poc_email = str(_poc.get("email", "") or "")
                        _poc_phone = str(_poc.get("phone", "") or "")
                    if _client_short:
                        client_name = _client_short
        except Exception:
            pass
        if pid in _active_procs:
            status = "running"
        elif proj.get("status") in ("complete", "done", "finished"):
            status = "complete"
        else:
            status = "idle"
            if yaml_path and os.path.exists(yaml_path):
                try:
                    _yaml_data = load_yaml(yaml_path)
                    _progress  = load_progress(yaml_path)
                    _pm        = compute_progress(_yaml_data, _progress)
                    if _pm and all(v.get("completed") for v in _pm.values()):
                        proj["status"] = "complete"
                        raw["projects"][pid] = proj
                        save_projects(raw)
                        status = "complete"
                except Exception:
                    pass
        _finding_count = 0
        if yaml_path and os.path.exists(yaml_path):
            try:
                _finding_count = len(load_findings(yaml_path))
            except Exception:
                pass
        result.append({
            "id":               pid,
            "name":             proj.get("name", pid),
            "client_name":      client_name,
            "client_short":     _client_short,
            "consultant":       _consultant,
            "consultant_email": _consultant_email,
            "poc_name":         _poc_name,
            "poc_email":        _poc_email,
            "poc_phone":        _poc_phone,
            "start_date":       _start,
            "end_date":         _end,
            "tool":             "gearbox",
            "project_dir":      project_dir,
            "status":           status,
            "finding_count":    _finding_count,
            "has_findings":     _finding_count > 0,
            "created":          proj.get("created", ""),
        })
    return jsonify(result)


@app.route('/api/projects/<project_id>/status')
def api_project_status(project_id):
    """Standardized status endpoint polled by Arbiter's scan_poll_worker."""
    raw = load_projects()
    if project_id not in raw.get("projects", {}):
        return jsonify({"error": "not found"}), 404

    running = project_id in _active_procs

    queue_position = None
    with _queue_lock:
        for i, job in enumerate(_job_queue):
            if job.get("project_id") == project_id:
                queue_position = i + 1
                break

    if running:
        overall = "running"
    elif queue_position is not None:
        overall = "queued"
    else:
        proj = raw["projects"][project_id]
        s = proj.get("status", "idle")
        if s in ("complete", "done", "finished"):
            overall = "complete"
        elif s == "error":
            overall = "error"
        else:
            # Dynamically derive completion from progress.json for projects
            # that finished before the status field was introduced.
            overall = "idle"
            yaml_path = proj.get("yaml_path", "")
            if yaml_path and os.path.exists(yaml_path):
                try:
                    _yaml_data = load_yaml(yaml_path)
                    _progress  = load_progress(yaml_path)
                    _pm        = compute_progress(_yaml_data, _progress)
                    if _pm and all(v.get("completed") for v in _pm.values()):
                        proj["status"] = "complete"
                        save_projects(raw)
                        overall = "complete"
                except Exception:
                    pass

    return jsonify({
        "project_id":     project_id,
        "status":         overall,
        "tool":           "gauntlet",
        "queue_position": queue_position,
    })


@app.route('/auth/change-password', methods=['GET', 'POST'])
def change_password():
    force = _auth.must_change_password()
    if request.method == 'POST':
        if not _auth.validate_csrf(request.form.get('csrf_token')):
            return render_template('change_password.html', error='Session expired \u2014 please try again.',
                                   force=force, csrf_token=_auth.generate_csrf())
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if force:
            new_user = request.form.get('new_username', '').strip()
            err = _auth.is_weak_username(new_user)
            if err:
                return render_template('change_password.html', error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            if len(new_pw) < 8:
                return render_template('change_password.html', error='Password must be at least 8 characters.',
                                       force=force, csrf_token=_auth.generate_csrf())
            if new_pw != confirm:
                return render_template('change_password.html', error='Passwords do not match.',
                                       force=force, csrf_token=_auth.generate_csrf())
            err = _auth.is_weak_password(new_pw, new_user)
            if err:
                return render_template('change_password.html', error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            _auth.update_credentials(new_user, new_pw)
            session['username'] = new_user
            return redirect(url_for('index'))
        else:
            current = request.form.get('current_password', '')
            if not _auth.check_current_password(current):
                return render_template('change_password.html', error='Current password is incorrect.',
                                       force=force, csrf_token=_auth.generate_csrf())
            if len(new_pw) < 8:
                return render_template('change_password.html', error='Password must be at least 8 characters.',
                                       force=force, csrf_token=_auth.generate_csrf())
            if new_pw != confirm:
                return render_template('change_password.html', error='Passwords do not match.',
                                       force=force, csrf_token=_auth.generate_csrf())
            err = _auth.is_weak_password(new_pw, _auth.get_username())
            if err:
                return render_template('change_password.html', error=err,
                                       force=force, csrf_token=_auth.generate_csrf())
            _auth.update_password(new_pw)
            return redirect(url_for('index'))
    return render_template('change_password.html', force=force, csrf_token=_auth.generate_csrf())


# ---------------------------------------------------------------------------
# Job queue helpers
# ---------------------------------------------------------------------------

def _load_execute_queue() -> None:
    global _job_queue
    try:
        if os.path.exists(_QUEUE_FILE):
            with open(_QUEUE_FILE) as _f:
                _job_queue = json.load(_f)
    except Exception:
        _job_queue = []


def _save_execute_queue() -> None:
    try:
        with open(_QUEUE_FILE, "w") as _f:
            json.dump(_job_queue, _f, indent=2)
    except Exception:
        pass


def _is_any_running() -> bool:
    return bool(_active_procs)


def _launch_gearbox_bg(project_id: str) -> None:
    """Launch gearbox for a project without requiring a SocketIO context."""
    raw = load_projects()
    pinfo = raw.get("projects", {}).get(project_id)
    if not pinfo:
        return
    if project_id in _active_procs:
        return
    yaml_path = pinfo.get("yaml_path", "")
    if not yaml_path or not os.path.isfile(yaml_path):
        return
    gearbox_path = os.path.join(_BASE_DIR, "..", "Gearbox", "gearbox.py")
    if not os.path.isfile(gearbox_path):
        gearbox_path = "gearbox.py"
    project_output_dir = os.path.dirname(os.path.abspath(yaml_path))
    flask_port = app.config.get("SERVER_PORT", 5700)
    ifaces     = get_all_interfaces()
    iface_list = [
        {"name": i["name"], "ip": i["ip"],
         "url": f"https://{i['ip']}:{flask_port}/join/{project_id}"}
        for i in ifaces
    ]
    cmd = ["sudo", "-E", "python3", gearbox_path, yaml_path,
           "--join-interfaces", json.dumps(iface_list),
           "--project-dir", project_output_dir]
    answer_q = queue.Queue()
    _answer_queues[project_id] = answer_q
    _console_buffer[project_id] = []
    _gearbox_log[project_id]    = []
    _observations[project_id]   = []
    _error_buffer[project_id]   = []
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=0,
        )
    except Exception as exc:
        socketio.emit("gearbox_error", {"error": str(exc)},
                      room=_room(project_id))
        _answer_queues.pop(project_id, None)
        return
    _active_procs[project_id] = proc
    socketio.emit("gearbox_started", {"pid": proc.pid}, room=_room(project_id))
    threading.Thread(target=_stdout_reader, args=(proc, project_id, answer_q), daemon=True).start()
    threading.Thread(target=_stderr_reader, args=(proc, project_id), daemon=True).start()


def _execute_queued_job(job: dict) -> None:
    project_id = job.get("project_id", "")
    if not project_id:
        return
    _launch_gearbox_bg(project_id)


def _dequeue_next() -> None:
    with _queue_lock:
        if not _job_queue or _is_any_running():
            return
        job = _job_queue.pop(0)
        _save_execute_queue()
    threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()


# ---------------------------------------------------------------------------
# API: Project template + remote execute
# ---------------------------------------------------------------------------

@app.route("/api/project-template")
def api_project_template():
    return jsonify({
        "tool": "gauntlet",
        "description": "Hardware security assessment platform",
        "fields": {
            "client_name":          {"type": "string",  "required": True,  "label": "Client Name"},
            "client_short":         {"type": "string",  "required": True,  "label": "Client Short Name"},
            "device":               {"type": "string",  "required": True,  "label": "Device Name"},
            "device_model":         {"type": "string",  "required": False, "label": "Device Model Number"},
            "device_sw_version":    {"type": "string",  "required": False, "label": "Device Software Version"},
            "start_date":           {"type": "date",    "required": False, "label": "Start Date"},
            "end_date":             {"type": "date",    "required": False, "label": "End Date"},
            "consultant_name":      {"type": "string",  "required": False, "label": "Consultant Name"},
            "consultant_title":     {"type": "string",  "required": False, "label": "Consultant Title"},
            "consultant_email":     {"type": "string",  "required": False, "label": "Consultant Email"},
            "poc_name":             {"type": "string",  "required": False, "label": "POC Name"},
            "poc_phone":            {"type": "string",  "required": False, "label": "POC Phone"},
            "poc_email":            {"type": "string",  "required": False, "label": "POC Email"},
        },
    })


@app.route("/api/execute-project", methods=["POST"])
def api_execute_project():
    data = request.get_json(force=True, silent=True) or {}
    execute = data.get("execute", True)

    _cs_raw = (data.get("client_short") or "").strip()
    _sd_raw = (data.get("start_date")   or "").strip()

    if _cs_raw:
        target_dir = str(_build_project_dir_structured(_cs_raw, _sd_raw))
    else:
        return jsonify({"error": "client_short is required"}), 400

    yaml_data     = _build_yaml(data)
    client_short  = (_cs_raw).replace(" ", "_").upper()
    device        = (data.get("device") or "device").strip().replace(" ", "_").replace("/", "-")
    yaml_filename = f"{client_short}_{device}.yaml"
    yaml_path     = os.path.join(target_dir, yaml_filename)

    with open(yaml_path, "w") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    projects_data = load_projects()
    project_id    = str(uuid.uuid4())
    project_name  = f"{data.get('client_name', 'Client')} — {data.get('device', 'Device')}"
    projects_data["projects"][project_id] = {
        "id":                 project_id,
        "name":               project_name,
        "yaml_path":          yaml_path,
        "created":            datetime.now().strftime("%Y-%m-%d"),
        "device_model_number": str(data.get("device_model", "") or "").strip(),
    }
    save_projects(projects_data)

    if not execute:
        return jsonify({"ok": True, "project_id": project_id, "queued": False, "started": False})

    job = {"project_id": project_id}
    with _queue_lock:
        if _is_any_running():
            position = len(_job_queue) + 1
            _job_queue.append(job)
            _save_execute_queue()
            return jsonify({"ok": True, "project_id": project_id, "queued": True, "position": position})

    threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()
    return jsonify({"ok": True, "project_id": project_id, "queued": False, "started": True})


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    _load_execute_queue()
    print(f"Gauntlet v{VERSION} — Hardware Security Assessment Platform")
    print("Listening on https://0.0.0.0:5700")
    app.config['SERVER_PORT'] = 5700
    socketio.run(app, debug=False, host='0.0.0.0', port=5700,
                 allow_unsafe_werkzeug=True, ssl_context=_auth.make_ssl_context())
