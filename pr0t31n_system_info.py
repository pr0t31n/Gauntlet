"""
pr0t31n_system_info — Cross-platform testing host information collector.

Gathers hostname, IP, network settings, OS, CPU, RAM, and hardware info
for display on Flask management app Summary pages.

Usage:
    import sys
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_system_info as _si
    info = _si.collect()    # returns dict
"""

import json
import os
import platform
import re
import socket
import subprocess
import sys

__all__ = ["collect"]

_CACHE: dict | None = None


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _hostname() -> str:
    return socket.gethostname()


def _os_info() -> dict:
    info = {
        "system":  platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }
    if platform.system() == "Darwin":
        ver = platform.mac_ver()[0]
        if ver:
            info["os_name"] = f"macOS {ver}"
        else:
            info["os_name"] = f"macOS ({info['release']})"
    elif platform.system() == "Linux":
        # Try /etc/os-release for distro name
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["os_name"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            info["os_name"] = f"Linux {info['release']}"
    else:
        info["os_name"] = f"{info['system']} {info['release']}"
    return info


def _cpu_info() -> dict:
    cpu: dict = {"model": "", "cores": 0, "threads": 0, "speed": ""}
    system = platform.system()

    if system == "Darwin":
        cpu["model"]   = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        cores          = _run(["sysctl", "-n", "hw.physicalcpu"])
        threads        = _run(["sysctl", "-n", "hw.logicalcpu"])
        speed          = _run(["sysctl", "-n", "hw.cpufrequency_max"])
        cpu["cores"]   = int(cores) if cores.isdigit() else 0
        cpu["threads"] = int(threads) if threads.isdigit() else 0
        if speed.isdigit():
            ghz = int(speed) / 1_000_000_000
            cpu["speed"] = f"{ghz:.2f} GHz"
    elif system == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                text = f.read()
            m = re.search(r"model name\s*:\s*(.+)", text)
            if m:
                cpu["model"] = m.group(1).strip()
            cpu["threads"] = text.count("processor\t:")
            # Physical cores
            phys = set()
            for m in re.finditer(r"core id\s*:\s*(\d+)", text):
                phys.add(m.group(1))
            cpu["cores"] = len(phys) if phys else cpu["threads"]
            sm = re.search(r"cpu MHz\s*:\s*([\d.]+)", text)
            if sm:
                mhz = float(sm.group(1))
                cpu["speed"] = f"{mhz / 1000:.2f} GHz"
        except Exception:
            pass
    return cpu


def _ram_info() -> dict:
    ram: dict = {"total_bytes": 0, "total_human": ""}
    system = platform.system()

    if system == "Darwin":
        val = _run(["sysctl", "-n", "hw.memsize"])
        if val.isdigit():
            ram["total_bytes"] = int(val)
    elif system == "Linux":
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(re.search(r"(\d+)", line).group(1))
                        ram["total_bytes"] = kb * 1024
                        break
        except Exception:
            pass

    b = ram["total_bytes"]
    if b > 0:
        gb = b / (1024 ** 3)
        ram["total_human"] = f"{gb:.0f} GB" if gb >= 1 else f"{b / (1024**2):.0f} MB"
    return ram


def _hardware_info() -> dict:
    hw: dict = {"model": "", "form_factor": "", "board": "", "serial": ""}
    system = platform.system()

    if system == "Darwin":
        hw["model"] = _run(["sysctl", "-n", "hw.model"])
        out = _run(["system_profiler", "SPHardwareDataType"])
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Model Name:"):
                hw["form_factor"] = line.split(":", 1)[1].strip()
            elif line.startswith("Model Identifier:"):
                hw["board"] = line.split(":", 1)[1].strip()
            elif line.startswith("Serial Number"):
                hw["serial"] = line.split(":", 1)[1].strip()
    elif system == "Linux":
        # DMI data (requires root or readable /sys)
        for key, path in [
            ("form_factor", "/sys/class/dmi/id/chassis_type"),
            ("board",       "/sys/class/dmi/id/board_name"),
            ("model",       "/sys/class/dmi/id/product_name"),
            ("serial",      "/sys/class/dmi/id/product_serial"),
        ]:
            try:
                with open(path) as f:
                    val = f.read().strip()
                if val and val != "Not Specified":
                    hw[key] = val
            except Exception:
                pass
        # Map chassis_type number to human-readable form factor
        _CHASSIS_MAP = {
            "1": "Other", "2": "Unknown", "3": "Desktop", "4": "Low-Profile Desktop",
            "5": "Pizza Box", "6": "Mini Tower", "7": "Tower", "8": "Portable",
            "9": "Laptop", "10": "Notebook", "11": "Hand-Held", "12": "Docking Station",
            "13": "All-in-One", "14": "Sub-Notebook", "15": "Space-Saving",
            "16": "Lunch Box", "17": "Main Server Chassis", "23": "Rack Mount Server",
            "24": "Sealed-Case PC", "25": "Multi-System", "30": "Tablet",
            "31": "Convertible", "32": "Detachable", "35": "Mini PC",
            "36": "Stick PC",
        }
        if hw["form_factor"].isdigit():
            hw["form_factor"] = _CHASSIS_MAP.get(hw["form_factor"], f"Type {hw['form_factor']}")
        # Try lshw fallback if board is empty
        if not hw["board"]:
            out = _run(["lshw", "-class", "system", "-short"], timeout=5)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "system":
                    hw["board"] = " ".join(parts[2:])
                    break
    return hw


def _active_interface() -> dict:
    """Detect the primary network interface used for testing."""
    iface: dict = {
        "name": "", "ip": "", "mac": "",
        "netmask": "", "broadcast": "", "gateway": "",
        "type": "",  # "static" or "dynamic"
        "subnet_cidr": "",
    }
    system = platform.system()

    if system == "Darwin":
        # Get default route interface
        route_out = _run(["route", "-n", "get", "default"])
        for line in route_out.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                iface["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("gateway:"):
                iface["gateway"] = line.split(":", 1)[1].strip()

        if iface["name"]:
            ifconfig = _run(["ifconfig", iface["name"]])
            for line in ifconfig.splitlines():
                line = line.strip()
                m = re.match(r"inet\s+([\d.]+)\s+netmask\s+(0x[0-9a-f]+)(?:\s+broadcast\s+([\d.]+))?", line)
                if m:
                    iface["ip"] = m.group(1)
                    # Convert hex netmask to dotted
                    hex_mask = m.group(2)
                    try:
                        mask_int = int(hex_mask, 16)
                        iface["netmask"] = f"{(mask_int >> 24) & 0xFF}.{(mask_int >> 16) & 0xFF}.{(mask_int >> 8) & 0xFF}.{mask_int & 0xFF}"
                        # CIDR prefix
                        iface["subnet_cidr"] = str(bin(mask_int).count("1"))
                    except Exception:
                        iface["netmask"] = hex_mask
                    if m.group(3):
                        iface["broadcast"] = m.group(3)
                em = re.match(r"ether\s+([0-9a-f:]+)", line)
                if em:
                    iface["mac"] = em.group(1)

            # Static vs DHCP — check networksetup
            hw_ports = _run(["networksetup", "-listallhardwareports"])
            # Find the service name for our interface
            service_name = ""
            lines = hw_ports.splitlines()
            for i, l in enumerate(lines):
                if iface["name"] in l:
                    # Service name is on the line above
                    for j in range(i - 1, -1, -1):
                        if "Hardware Port:" in lines[j]:
                            service_name = lines[j].split(":", 1)[1].strip()
                            break
                    break
            if service_name:
                ip_info = _run(["networksetup", "-getinfo", service_name])
                if "DHCP" in ip_info:
                    iface["type"] = "dynamic (DHCP)"
                elif "Manual" in ip_info or "manual" in ip_info:
                    iface["type"] = "static"
                else:
                    iface["type"] = "unknown"

    elif system == "Linux":
        # Get default route interface
        route_out = _run(["ip", "route", "show", "default"])
        m = re.search(r"default via\s+([\d.]+)\s+dev\s+(\S+)", route_out)
        if m:
            iface["gateway"] = m.group(1)
            iface["name"] = m.group(2)

        if iface["name"]:
            addr_out = _run(["ip", "-4", "addr", "show", iface["name"]])
            m = re.search(r"inet\s+([\d.]+)/(\d+)", addr_out)
            if m:
                iface["ip"] = m.group(1)
                iface["subnet_cidr"] = m.group(2)
                # Convert CIDR to netmask
                cidr = int(m.group(2))
                mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
                iface["netmask"] = f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"
            bm = re.search(r"brd\s+([\d.]+)", addr_out)
            if bm:
                iface["broadcast"] = bm.group(1)

            link_out = _run(["ip", "link", "show", iface["name"]])
            em = re.search(r"link/ether\s+([0-9a-f:]+)", link_out)
            if em:
                iface["mac"] = em.group(1)

            # Static vs DHCP — check NetworkManager or systemd-networkd
            nm = _run(["nmcli", "-t", "-f", "ipv4.method", "connection", "show", iface["name"]])
            if "manual" in nm.lower():
                iface["type"] = "static"
            elif "auto" in nm.lower() or "dhcp" in nm.lower():
                iface["type"] = "dynamic (DHCP)"
            else:
                # Check /etc/network/interfaces (Debian/Kali)
                try:
                    with open("/etc/network/interfaces") as f:
                        content = f.read()
                    if re.search(rf"iface\s+{re.escape(iface['name'])}\s+inet\s+static", content):
                        iface["type"] = "static"
                    elif re.search(rf"iface\s+{re.escape(iface['name'])}\s+inet\s+dhcp", content):
                        iface["type"] = "dynamic (DHCP)"
                except Exception:
                    iface["type"] = "unknown"

    return iface


def _public_ip() -> dict:
    """Detect external/public IP via DNS (fast) then HTTP fallback."""
    pub: dict = {"ip": "", "source": ""}
    # Method 1: DNS — fastest, no HTTP overhead
    ip = _run(["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], timeout=5)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        pub["ip"] = ip
        pub["source"] = "dns"
        return pub
    # Method 2: HTTP fallback
    try:
        from urllib.request import urlopen, Request
        req = Request("https://ifconfig.me/ip", headers={"User-Agent": "curl/8.0"})
        with urlopen(req, timeout=5) as resp:
            ip = resp.read().decode("utf-8", errors="ignore").strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            pub["ip"] = ip
            pub["source"] = "http"
            return pub
    except Exception:
        pass
    # Method 3: curl fallback (if urllib blocked by proxy/cert issues)
    ip = _run(["curl", "-s", "--max-time", "5", "https://ifconfig.me/ip"], timeout=8)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        pub["ip"] = ip
        pub["source"] = "http"
    return pub


def collect(*, use_cache: bool = True) -> dict:
    """Collect all system info. Results are cached after first call."""
    global _CACHE
    if use_cache and _CACHE is not None:
        return _CACHE

    result = {
        "hostname":  _hostname(),
        "os":        _os_info(),
        "cpu":       _cpu_info(),
        "ram":       _ram_info(),
        "hardware":  _hardware_info(),
        "interface": _active_interface(),
        "public_ip": _public_ip(),
    }

    _CACHE = result
    return result


def as_json(*, indent: int = 2) -> str:
    return json.dumps(collect(), indent=indent, default=str)


if __name__ == "__main__":
    print(as_json())
