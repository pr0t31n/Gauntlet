# Gauntlet

**Web-based hardware security assessment platform** — project management, real-time gearbox.py orchestration, multi-device collaboration, and automated findings collection in a single Flask application.

Gauntlet provides a structured, browser-based interface for hardware security assessments. It manages the full engagement lifecycle: create a project with device and interface definitions, launch `gearbox.py` to drive the 30+ tool testing pipeline, interact with live prompts from any device, collect and parse evidence from Nessus/Nmap/sslscan/nuclei and more, track module completion across every interface instance, and export structured findings for reporting.

---

## Features

- **Structured project management** — YAML-backed project files define devices, subdevices, interfaces, and instances. Auto-migrates human-readable instance keys from auto-generated placeholders.
- **Real-time gearbox orchestration** — Launches `gearbox.py` as a managed subprocess, streams stdout/stderr to the browser console, and handles interactive prompts via a modal dialog.
- **Multi-device collaboration** — Socket.IO rooms let phones, tablets, and other machines join any active session. All devices see live console output and can respond to prompts.
- **Photo QR join** — Generates per-network-interface QR codes for mobile devices to join a project session and upload photos directly from the device camera.
- **Automated evidence parsing** — Uploaded evidence files are auto-detected and parsed for findings: Nessus XML/CSV, Nmap XML, sslscan, testssl.sh, ssh-audit, shcheck, nuclei JSON, and PCAP.
- **Findings management** — Deduplicated findings by UUID with inline risk override, soft-delete with audit trail, manual rename/group, and JSONL persistence.
- **Module completion tracking** — Per-instance module status (`complete`, `skipped`, `na`, `error`) tracked in `progress.json`. Evidence validation enforces required files before marking completion.
- **Graceful shutdown** — SIGTERM allows gearbox to run cleanup routines; SIGKILL fallback after 8 seconds. Full process tree termination via `psutil`.
- **Export** — JSON export of full project state, ZIP export of project directory with portable relative paths.
- **20-palette theme system** — Light and dark modes across 20 color palettes, persisted in `localStorage`.

---

## Requirements

### Python
- Python 3.10+
- `flask>=3.0.0`
- `flask-socketio>=5.3.6`
- `pyyaml>=6.0.1`
- `eventlet>=0.35.0`
- `dpkt` (optional — PCAP parsing)
- `psutil` (optional — graceful process tree shutdown)
- `netifaces` (optional — cross-platform interface enumeration for QR URLs)

Install dependencies:
```bash
pip install -r requirements.txt
```

### Gearbox
- `gearbox.py` must be on the system (path specified at launch time in the UI)
- All external tools (nmap, nuclei, nessus, sslscan, etc.) are called by gearbox, not Gauntlet directly

---

## Installation

```bash
git clone https://github.com/yourorg/gauntlet
cd gauntlet
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000** in your browser.

---

## Usage

### 1. Create a project

Navigate to **New Project** and fill in:
- Engagement metadata (client name, consultant, POC, dates)
- Device details (name, model number, software version)
- Subdevices with interface types (USB, Ethernet, Serial, HDMI, etc.) and instance locations

On submission, Gauntlet writes a `CLIENT_DEVICE.yaml` to your chosen directory and registers it in `projects.json`.

### 2. Launch Gearbox

On the **Interactive Testing** tab:
1. Enter the path to `gearbox.py` (relative to Gauntlet's working directory)
2. Click **▶ Start Gearbox** — the process starts with your YAML and project directory passed as arguments
3. Console output streams live to the browser
4. When gearbox emits a prompt, a modal appears — type your response and press **Send**
5. Click **■ Terminate** to stop the process at any time

### 3. Collect evidence

Upload evidence files via the **Modules** tab. Gauntlet auto-detects the tool from file contents and extracts findings into the normalized findings store.

### 4. Review findings

The **Findings** tab lists all deduplicated findings with risk level, tool source, host/port, and CVE IDs. Adjust risk levels inline, delete false positives (soft-delete preserves audit trail), or rename/group findings for reporting.

### 5. Export

- **JSON Export** — full project state including all instance details, findings, and subnet/port/URL structure
- **ZIP Export** — portable project directory archive with relative paths

---

## Project YAML Structure

```yaml
client_name: Acme Corporation
client_short: ACME
consultant:
  name: Jane Smith
  title: Senior Security Engineer
  email: jsmith@firm.com
client_poc:
  name: John Doe
  phone: +1 555-000-0000
  email: jdoe@acme.com
year: 2026
device: Industrial Control Unit
device_model_number: ICU-3000-A
device_software_version: v2.4.1
version: "1.0"
start_date: 01/15/2026
end_date: 01/30/2026
subdevices:
  main_board:
    name: Main Board
    interfaces:
      USB:
        front_left:
          location: Front panel left
      Ethernet:
        port_1:
          location: Port 1
        port_2:
          location: Port 2
```

Instance keys (`front_left`, `port_1`, etc.) are derived from the `location` field and auto-migrated from placeholder names (`instance_1`) on first load.

---

## Supported Testing Modules

Gauntlet tracks completion and parses evidence for the following modules, all driven by `gearbox.py`:

| Module | Interface Type | Tools Used | Notes |
|--------|---------------|------------|-------|
| **Photo** | All | gowitness | Required — cannot be skipped |
| **NmapLive** | Ethernet | nmap `-sn` | Live host detection |
| **NmapPort** | Ethernet | nmap `-sV` | Port + service detection |
| **BannerGrab** | Ethernet | socket, curl | Service banner collection |
| **Web** | Ethernet | curl, gowitness, wget, openssl | Web screenshots + spider |
| **SSL** | Ethernet | sslscan, testssl.sh, shcheck | TLS cipher + cert analysis |
| **SSH** | Ethernet | nmap, ssh-audit | SSH enumeration + hardening |
| **SMB** | Ethernet | nmap, smbmap, responder | SMB share enumeration |
| **NFS** | Ethernet | nmap | NFS mount enumeration |
| **FTP** | Ethernet | nmap | FTP enumeration |
| **Nessus** | Ethernet | Nessus (enterprise) | Vulnerability scan |
| **Nuclei** | Ethernet | nuclei | Template-based CVE scanning |
| **Responder** | Ethernet | responder | LLMNR/NBT-NS poisoning |
| **ConfigDiscovery** | Ethernet | tcpdump | Passive config discovery |
| **TrafficCollector** | Ethernet | tcpdump, tshark | Packet capture |
| **Ethtool** | Ethernet | ethtool | Interface statistics |
| **Keyboard** | USB | hid-tools | HID keyboard enumeration |
| **KeyCombos** | USB | hid-tools | HID key combo injection |
| **Mouse** | USB | hid-tools | HID mouse enumeration |
| **UsbPower** | USB | usbmon | USB power monitoring |
| **BashBunny** | USB | bash-bunny | Payload execution |
| **Video** | HDMI | ffmpeg, v4l2-ctl | HDMI input/output testing |
| **EDID** | HDMI | get-edid, edid-decode | EDID parsing |
| **HDMI DDC** | HDMI | ddcutil, ddccontrol | DDC control testing |
| **HDMI HDCP** | HDMI | hdcp-check, v4l2-ctl | HDCP detection |
| **HDMI CEC** | HDMI | cec-client | CEC command testing |
| **Serial** | Serial | sigrok, minicom | Serial protocol analysis |
| **CAN** | CAN | candump, canplayer | CAN bus analysis |
| **Zigbee** | RF | wireshark, scapy | Zigbee sniffing |
| **RFID** | RF | proxmark3 | RFID cloning + analysis |

---

## Output Structure

```
<project_dir>/
├── CLIENT_SHORT/
│   └── DEVICE/
│       ├── _Tools/
│       │   └── <interface_lower>/
│       │       └── Photo/             gowitness screenshots
│       └── <subdevice_name>/
│           ├── _Photos/
│           │   ├── FRONT/Photo/
│           │   ├── BACK/Photo/
│           │   └── INTERFACES/Photo/
│           └── <Interface>/
│               └── <instance>/
│                   ├── Photo/         *.jpg
│                   ├── NmapLive/      *.xml, *.txt
│                   ├── NmapPort/      {ip}_{port}.xml
│                   ├── SSL/           {ip}_{port}_info.txt
│                   ├── SSH/           *.txt, *.json
│                   ├── Web/
│                   │   ├── screenshots/   *.png
│                   │   └── spider/
│                   ├── Nessus/        *.nessus, *.csv, *.html
│                   ├── Nuclei/        *.json
│                   ├── TrafficCollector/  *.pcap
│                   └── <Module>/
├── findings.jsonl                     Deduplicated findings (one per line)
├── deleted_findings.jsonl             Soft-deleted findings (audit trail)
├── risk_overrides.yaml                Manual risk adjustments
├── progress.json                      Module completion state
├── gearbox_log.jsonl                  Structured gearbox logs
├── observations.jsonl                 Tool observations
├── gauntlet_log.jsonl                 Session activity log
└── errors.jsonl                       Error log
```

### findings.jsonl schema

```json
{
  "id":          "uuid",
  "title":       "SSL/TLS: TLS 1.0 Enabled",
  "risk":        "Medium",
  "description": "...",
  "ip":          "192.168.1.50",
  "port":        "443",
  "cve_ids":     ["CVE-2021-3449"],
  "output_file": "relative/path/to/evidence",
  "source":      "sslscan",
  "tool":        "sslscan"
}
```

Risk values: `Critical`, `High`, `Medium`, `Low`, `Informational`

---

## Gearbox Protocol

Gauntlet communicates with `gearbox.py` via structured stdout markers:

| Marker | Format | Purpose |
|--------|--------|---------|
| `__GB_PROMPT__:` | JSON | Request user input (triggers modal dialog) |
| `__GB_STATUS__:` | JSON | Module progress update |
| `__GB_FINDING__:` | JSON | Extracted finding for immediate ingestion |
| `__GB_LOG__:` | JSON | Structured log entry |

Prompt responses are written to gearbox's stdin. Multiple web clients in the same project room see prompts simultaneously; the first response wins.

---

## Multi-Device Collaboration

Any device on the network can join an active project session by scanning the QR code displayed in the UI. The `/join/<project_id>` page provides:
- Live console output
- Prompt response (for distributed teams)
- Photo upload from device camera

Gauntlet generates per-network-interface QR codes to handle lab environments with multiple NICs.

---

## Nessus Integration

Pass Nessus credentials via environment variables before starting Gauntlet:

```bash
export NESSUS_USER=admin
export NESSUS_PASS=yourpassword
python app.py
```

Gauntlet forwards these to gearbox.py as `--nessus-user` / `--nessus-pass` CLI arguments.

---

## Cross-Platform Notes

| Platform | Support | Notes |
|----------|---------|-------|
| Linux | Full | All features supported |
| macOS | Full | `netifaces` recommended for accurate QR URLs |
| Windows | Partial | Process tree shutdown requires `psutil`; no `/proc` fallback |
| Mobile browsers | Full | Chrome, Safari, Firefox — join page + photo upload |

---

## Browser Support

Chrome 120+, Firefox 121+, Safari 17+, Edge 120+, and all modern mobile browsers. JavaScript required.

---

## Contributors

Gauntlet is built on the following open-source libraries and frameworks:

| Library / Tool | Author / Maintainer | Link |
|----------------|-------------------|------|
| **Flask** | Armin Ronacher @mitsuhiko | https://github.com/pallets/flask |
| **Flask-SocketIO** | Miguel Grinberg @miguelgrinberg | https://github.com/miguelgrinberg/flask-socketio |
| **Socket.IO** | Guillermo Rauch @rauchg & Socket.IO contributors | https://socket.io |
| **eventlet** | eventlet contributors | https://eventlet.net |
| **PyYAML** | Kirill Simonov & PyYAML team | https://pyyaml.org |
| **psutil** | Giampaolo Rodola @giampaolo | https://github.com/giampaolo/psutil |
| **dpkt** | Dug Song & kbandla | https://github.com/kbandla/dpkt |
| **netifaces** | Alastair Houghton | https://github.com/al45tair/netifaces |
| **gearbox.py** | See gearbox/README.md for the full tool dependency list | ../gearbox/ |
