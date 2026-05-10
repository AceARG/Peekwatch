import sys
import re
import time
import socket
import ipaddress
import platform
import subprocess
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SYSTEM = platform.system().lower()

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ── Session state ──────────────────────────────────────────────────────────────
_lock         = threading.Lock()
_actors: dict = {}          # ip -> actor dict
_alerts       = deque(maxlen=500)
_start        = time.time()
_total_alerts = 0

LOCAL_IP   = ""
GATEWAY_IP = ""

# Geo resolution
_geo_cache: dict   = {}
_geo_pending: set  = set()
_geo_pool          = ThreadPoolExecutor(max_workers=5)
_geo_req_lock      = threading.Lock()
_geo_last_req      = 0.0    # rate-limit: ip-api.com free = 45/min

# Hostname resolution
_host_cache: dict  = {}
_host_pending: set = set()
_host_pool         = ThreadPoolExecutor(max_workers=20)

# Left panel cache
_left_state = {"panel": None, "order": None, "geo": {}}

# ── Threat tables ──────────────────────────────────────────────────────────────
SENSITIVE_PORTS = {21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017}
HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 3389}  # critical if reachable

TARGET_SERVICES = {
    21:    "FTP server",
    22:    "SSH / Remote shell",
    23:    "Telnet (insecure remote access)",
    25:    "Mail server (SMTP)",
    53:    "DNS server",
    80:    "Web server",
    110:   "POP3 mail",
    135:   "Windows RPC",
    139:   "NetBIOS file sharing",
    143:   "IMAP mail",
    443:   "HTTPS server",
    445:   "SMB file sharing",
    1433:  "Microsoft SQL Server",
    3306:  "MySQL database",
    3389:  "Remote Desktop (RDP)",
    5432:  "PostgreSQL database",
    5900:  "VNC remote desktop",
    6379:  "Redis database",
    8080:  "Alt web server",
    8443:  "Alt HTTPS server",
    27017: "MongoDB database",
}


def target_service(port: int) -> str:
    return TARGET_SERVICES.get(port, f"Port {port} probe")


def intent_label(port, proto: str) -> str:
    """Plain-English description of what an inbound attempt is trying to do."""
    if proto == "ICMP":
        return "Ping sweep / host discovery"
    if port is None:
        return "Unknown probe"
    labels = {
        21:    "Attempting FTP access",
        22:    "Attempting SSH login",
        23:    "Attempting Telnet login",
        25:    "Probing mail server",
        80:    "Probing web server",
        135:   "Probing Windows RPC",
        139:   "Probing NetBIOS",
        443:   "Probing HTTPS server",
        445:   "Attempting SMB / file share access",
        1433:  "Probing SQL Server",
        3306:  "Probing MySQL database",
        3389:  "Attempting Remote Desktop login",
        5432:  "Probing PostgreSQL database",
        5900:  "Attempting VNC remote desktop",
        6379:  "Probing Redis database",
        8080:  "Probing alt web server",
        27017: "Probing MongoDB database",
    }
    return labels.get(port, f"Probing port {port}")


def compute_risk(actor: dict) -> tuple:
    ports    = actor["ports"]
    attempts = actor["attempts"]
    if len(ports) >= 10:
        return "PORT SCAN", "bold red"
    if ports & HIGH_RISK_PORTS and attempts >= 3:
        return "HIGH RISK", "red"
    if ports & HIGH_RISK_PORTS:
        return "HIGH RISK", "red"
    if ports & SENSITIVE_PORTS and attempts >= 5:
        return "PROBING", "yellow"
    if ports & SENSITIVE_PORTS:
        return "SUSPICIOUS", "yellow"
    if attempts >= 20:
        return "PERSISTENT", "yellow"
    return "LOW", "dim"


# ── Network helpers ────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def get_gateway_ip() -> str:
    try:
        if SYSTEM == "windows":
            out = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        else:
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True,
            ).stdout
            m = re.search(r"default via (\S+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def is_external(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return not (
            addr.is_private or addr.is_loopback or
            addr.is_multicast or addr.is_reserved or
            addr.is_link_local or addr.is_unspecified
        )
    except ValueError:
        return False


# ── Geo resolution ─────────────────────────────────────────────────────────────

GEO_MIN_INTERVAL = 1.4  # seconds between requests (safe under 45/min)


def _do_geo(ip: str):
    global _geo_last_req
    with _geo_req_lock:
        wait = GEO_MIN_INTERVAL - (time.time() - _geo_last_req)
        if wait > 0:
            time.sleep(wait)
        _geo_last_req = time.time()
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,org,as"},
            timeout=5,
        )
        data = r.json()
        _geo_cache[ip] = data if data.get("status") == "success" else {}
    except Exception:
        _geo_cache[ip] = {}
    _geo_pending.discard(ip)


def get_geo(ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]
    if ip not in _geo_pending:
        _geo_pending.add(ip)
        _geo_pool.submit(_do_geo, ip)
    return {}


# ── Hostname resolution ────────────────────────────────────────────────────────

def _do_resolve(ip: str):
    try:
        _host_cache[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        _host_cache[ip] = ip
    _host_pending.discard(ip)


def fmt_host(ip: str, width: int = 24) -> str:
    if ip not in _host_cache:
        if ip not in _host_pending:
            _host_pending.add(ip)
            _host_pool.submit(_do_resolve, ip)
        return ip
    name = _host_cache[ip]
    return name[:width] if len(name) > width else name


# ── Packet capture ─────────────────────────────────────────────────────────────

def on_packet(pkt):
    global _total_alerts
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if dst != LOCAL_IP:
        return
    if not is_external(src):
        return

    proto = None
    port  = None

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        # Only SYN (new attempt) — skip SYN+ACK (response to our outbound)
        if not (flags & 0x02) or (flags & 0x10):
            return
        proto = "TCP"
        port  = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        port  = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    else:
        return

    ts      = datetime.now().strftime("%H:%M:%S")
    service = target_service(port) if port else "ICMP"
    intent  = intent_label(port, proto)

    with _lock:
        _total_alerts += 1
        if src not in _actors:
            _actors[src] = {
                "attempts":   0,
                "ports":      set(),
                "protos":     set(),
                "first_seen": ts,
                "last_seen":  ts,
            }
        actor = _actors[src]
        actor["attempts"] += 1
        actor["last_seen"] = ts
        if port:
            actor["ports"].add(port)
        actor["protos"].add(proto)

        _alerts.append({
            "ts":      ts,
            "src":     src,
            "proto":   proto,
            "port":    port,
            "service": service,
            "intent":  intent,
        })

    # Trigger background enrichment
    get_geo(src)
    if src not in _host_cache and src not in _host_pending:
        _host_pending.add(src)
        _host_pool.submit(_do_resolve, src)


# ── UI ─────────────────────────────────────────────────────────────────────────

def fmt_bytes(n: int) -> str:
    if n < 1024:      return f"{n}B"
    if n < 1_048_576: return f"{n // 1024}K"
    return f"{n // 1_048_576}M"


def _build_actor_panel(top: list) -> Panel:
    tbl = Table(
        show_header=True, header_style="bold bright_cyan",
        box=box.SIMPLE_HEAVY, show_lines=False, expand=True,
    )
    tbl.add_column("#",        style="dim",         width=3)
    tbl.add_column("Source",   style="bold red",    no_wrap=True, min_width=16)
    tbl.add_column("Country",  style="bold white",  width=14)
    tbl.add_column("ISP",      style="dim",         min_width=14)
    tbl.add_column("Ports hit",style="yellow",      width=14)
    tbl.add_column("Tries",    style="cyan",        width=5, justify="right")
    tbl.add_column("Risk",     style="bold",        width=12)

    for i, (ip, actor) in enumerate(top, 1):
        geo     = _geo_cache.get(ip, {})
        country = geo.get("country", "...") if geo else "..."
        isp     = geo.get("isp", "...") if geo else "..."
        isp     = (isp[:16] + "..") if len(isp) > 18 else isp

        sorted_ports = sorted(actor["ports"])
        ports_str = ", ".join(str(p) for p in sorted_ports[:4])
        if len(sorted_ports) > 4:
            ports_str += f" +{len(sorted_ports) - 4}"

        risk_label, risk_style = compute_risk(actor)

        tbl.add_row(
            str(i),
            fmt_host(ip),
            country,
            isp,
            ports_str or "ICMP",
            str(actor["attempts"]),
            f"[{risk_style}]{risk_label}[/{risk_style}]",
        )

    panel = Panel(
        tbl,
        title="[bold white]Threat Actors[/bold white]",
        subtitle="[dim]updates when ranking changes[/dim]",
        border_style="bright_red", box=box.ROUNDED,
    )

    order   = tuple(ip for ip, _ in top)
    geo_snp = {ip: _geo_cache.get(ip) for ip, _ in top}
    host_snp = {ip: _host_cache.get(ip) for ip, _ in top}
    _left_state.update(panel=panel, order=order, geo=geo_snp, hosts=host_snp)
    return panel


def _get_actor_panel(top: list) -> Panel:
    if _left_state["panel"] is None:
        return _build_actor_panel(top)
    order = tuple(ip for ip, _ in top)
    if order != _left_state["order"]:
        return _build_actor_panel(top)
    for ip, _ in top:
        if _geo_cache.get(ip) != _left_state["geo"].get(ip):
            return _build_actor_panel(top)
        if _host_cache.get(ip) != _left_state.get("hosts", {}).get(ip):
            return _build_actor_panel(top)
    return _left_state["panel"]


def build_ui() -> Layout:
    elapsed = max(int(time.time() - _start), 1)
    h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60

    with _lock:
        total    = _total_alerts
        n_actors = len(_actors)
        top      = sorted(_actors.items(), key=lambda x: x[1]["attempts"], reverse=True)
        recent   = list(_alerts)[-30:]
        port_counts: dict = defaultdict(int)
        for a in _alerts:
            if a["port"]:
                port_counts[a["port"]] += 1

    top_port     = max(port_counts, key=port_counts.get) if port_counts else None
    top_port_str = f":{top_port} ({target_service(top_port)})" if top_port else "-"

    header_txt = (
        f"  [bold cyan]Alerts:[/bold cyan]  {total:,}   "
        f"[bold cyan]Sources:[/bold cyan]  {n_actors}   "
        f"[bold cyan]Top target:[/bold cyan]  {top_port_str}   "
        f"[bold cyan]Uptime:[/bold cyan]  {h:02d}:{m:02d}:{s:02d}   "
        f"[bold cyan]This PC:[/bold cyan]  {LOCAL_IP}"
    )

    actor_panel = _get_actor_panel(top[:20])

    feed_tbl = Table(
        show_header=True, header_style="bold bright_cyan",
        box=box.SIMPLE_HEAVY, show_lines=False, expand=True,
    )
    feed_tbl.add_column("Time",      style="dim",         width=10, no_wrap=True)
    feed_tbl.add_column("Source",    style="bold red",    no_wrap=True, min_width=16)
    feed_tbl.add_column("Country",   style="bold white",  width=14)
    feed_tbl.add_column("ISP",       style="dim",         min_width=14)
    feed_tbl.add_column("Proto",     style="dim",         width=6)
    feed_tbl.add_column("Port",      style="yellow",      width=6, justify="right")
    feed_tbl.add_column("What they want", style="dim")

    for a in reversed(recent):
        geo     = get_geo(a["src"])
        country = geo.get("country", "...") if geo else "..."
        isp     = geo.get("isp", "...") if geo else "..."
        isp     = (isp[:16] + "..") if len(isp) > 18 else isp
        feed_tbl.add_row(
            a["ts"],
            fmt_host(a["src"]),
            country,
            isp,
            a["proto"],
            str(a["port"]) if a["port"] else "-",
            a["intent"],
        )

    layout = Layout()
    layout.split_column(
        Layout(Panel(header_txt, border_style="bright_red", box=box.ROUNDED), size=3),
        Layout(name="main"),
    )
    layout["main"].split_row(
        Layout(actor_panel, ratio=2),
        Layout(
            Panel(feed_tbl, title="[bold white]Live Alerts[/bold white]",
                  subtitle="[dim]newest first[/dim]",
                  border_style="bright_red", box=box.ROUNDED),
            ratio=3,
        ),
    )
    return layout


# ── Export ─────────────────────────────────────────────────────────────────────

def export_session(iface: str) -> str:
    end_dt   = datetime.now()
    start_dt = datetime.fromtimestamp(_start)
    elapsed  = max(int(time.time() - _start), 1)
    h, m, s  = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60

    date_str  = start_dt.strftime("%Y-%m-%d")
    start_str = start_dt.strftime("%H-%M-%S")
    end_str   = end_dt.strftime("%H-%M-%S")
    filename  = f"peekwatch_{date_str}_{start_str}_to_{end_str}.txt"

    with _lock:
        total    = _total_alerts
        actors   = sorted(_actors.items(), key=lambda x: x[1]["attempts"], reverse=True)
        all_alerts = list(_alerts)
        port_counts: dict = defaultdict(int)
        for a in all_alerts:
            if a["port"]:
                port_counts[a["port"]] += 1

    sep  = "=" * 72
    dash = "-" * 72

    lines = [
        "PEEKWATCH -- Threat Session Report",
        sep,
        f"Date:           {start_dt.strftime('%Y-%m-%d')}",
        f"Time range:     {start_dt.strftime('%H:%M:%S')}  to  {end_dt.strftime('%H:%M:%S')}  ({h:02d}h {m:02d}m {s:02d}s)",
        f"This PC:        {LOCAL_IP or 'unknown'}",
        f"Gateway:        {GATEWAY_IP or 'unknown'}",
        f"Interface:      {iface or 'default'}",
        "",
        "SESSION STATS",
        dash,
        f"Total alerts:       {total:,}",
        f"Unique sources:     {len(actors)}",
    ]

    if port_counts:
        top_port = max(port_counts, key=port_counts.get)
        lines.append(f"Most targeted port: {top_port} ({target_service(top_port)}) -- {port_counts[top_port]} attempts")

    lines += [
        "",
        "THREAT ACTORS",
        dash,
        f"{'#':<4} {'IP':<18} {'Hostname':<28} {'Country':<16} {'City':<14} {'ISP':<28} {'ASN':<16} {'Ports Hit':<20} {'Tries':>5} {'Risk'}",
        "-" * 160,
    ]

    for i, (ip, actor) in enumerate(actors, 1):
        geo      = _geo_cache.get(ip, {})
        hostname = _host_cache.get(ip, ip)
        hostname = hostname if hostname != ip else "-"
        country  = geo.get("country", "Unknown") if geo else "Unknown"
        city     = geo.get("city", "-") if geo else "-"
        isp_name = geo.get("isp", "-") if geo else "-"
        asn      = geo.get("as", "-") if geo else "-"
        ports    = ", ".join(str(p) for p in sorted(actor["ports"])) if actor["ports"] else "ICMP only"
        risk_label, _ = compute_risk(actor)
        lines.append(
            f"{i:<4} {ip:<18} {hostname:<28} {country:<16} {city:<14} {isp_name:<28} {asn:<16} {ports:<20} {actor['attempts']:>5} {risk_label}"
        )

    lines += [
        "",
        "PORT TARGETING BREAKDOWN",
        dash,
        f"  {'Port':<8} {'Service':<30} {'Attempts':>8} {'% of alerts'}",
        "  " + "-" * 56,
    ]
    for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True):
        pct = count / max(total, 1) * 100
        lines.append(f"  {port:<8} {target_service(port):<30} {count:>8}   ({pct:.1f}%)")

    lines += [
        "",
        "FULL ALERT LOG",
        dash,
        f"  {'Time':<10} {'Source':<18} {'Country':<16} {'ISP':<28} {'Proto':<6} {'Port':<6} {'Intent'}",
        "  " + "-" * 110,
    ]
    for a in all_alerts:
        geo     = _geo_cache.get(a["src"], {})
        country = geo.get("country", "-") if geo else "-"
        isp_name = geo.get("isp", "-") if geo else "-"
        isp_name = (isp_name[:26] + "..") if len(isp_name) > 28 else isp_name
        lines.append(
            f"  {a['ts']:<10} {a['src']:<18} {country:<16} {isp_name:<28} "
            f"{a['proto']:<6} {str(a['port']) if a['port'] else '-':<6} {a['intent']}"
        )

    lines += [
        "",
        sep,
        f"Generated by peekwatch  --  {end_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filename


# ── Admin / setup ──────────────────────────────────────────────────────────────

def is_admin() -> bool:
    if SYSTEM == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os
        return os.geteuid() == 0
    except AttributeError:
        return False


def usage():
    console.print("""
[bold bright_red]PEEKWATCH[/bold bright_red]  [dim]// inbound threat monitor — who is trying to peek at your machine[/dim]

[bold cyan]Usage:[/bold cyan]
  peekwatch                   Monitor all inbound external traffic
  peekwatch -i <interface>    Capture on a specific interface
  peekwatch -h                Show this help

[bold cyan]Examples:[/bold cyan]
  peekwatch
  peekwatch -i Wi-Fi
  peekwatch -i eth0

[bold cyan]What it monitors:[/bold cyan]
  TCP SYN     Inbound connection attempts (new sessions only, not responses)
  UDP         Inbound packets from external IPs
  ICMP        Ping sweeps and host discovery probes

[bold cyan]What it shows:[/bold cyan]
  Source IP   Reverse DNS hostname when available
  Country     Where the probe is coming from
  ISP / ASN   Who owns the source IP
  Port        What service they are targeting
  Intent      Plain-English description of what they want
  Risk level  LOW / SUSPICIOUS / PROBING / HIGH RISK / PORT SCAN

[bold cyan]On exit:[/bold cyan]
  A full session report is saved automatically as:
  peekwatch_YYYY-MM-DD_HH-MM-SS_to_HH-MM-SS.txt

[bold cyan]Notes:[/bold cyan]
  Requires admin / root privileges.
  Windows: Npcap must be installed  (https://npcap.com)
  Linux:   libpcap must be installed
  Best results with a direct internet connection.
  Behind NAT: you will see traffic that your router forwards to your machine.
  Geo data resolves in the background -- country/ISP appears within a few seconds.
  Press Ctrl+C to stop.
""")


def main():
    global LOCAL_IP, GATEWAY_IP

    iface = None

    try:
        if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
            usage()
            sys.exit(0)

        args = sys.argv[1:]
        i    = 0
        while i < len(args):
            if args[i] == "-i" and i + 1 < len(args):
                iface = args[i + 1]; i += 2
            else:
                console.print(f"[red]Unknown argument:[/red] {args[i]}")
                sys.exit(2)

        if not SCAPY_OK:
            console.print("[red]Missing dependency:[/red] scapy is not installed.")
            console.print("  pip install scapy")
            sys.exit(1)

        if not is_admin():
            console.print("[red]Error:[/red] Packet capture requires admin/root privileges.")
            if SYSTEM == "windows":
                console.print("  Run this terminal as Administrator.")
            else:
                console.print("  Run with: sudo peekwatch")
            sys.exit(1)

        LOCAL_IP   = get_local_ip()
        GATEWAY_IP = get_gateway_ip()

        if not LOCAL_IP:
            console.print("[red]Error:[/red] Could not detect local IP address.")
            sys.exit(1)

        console.print(Panel(
            f"  [bold cyan]This PC:    [/bold cyan]  {LOCAL_IP}\n"
            f"  [bold cyan]Gateway:    [/bold cyan]  {GATEWAY_IP or 'unknown'}\n"
            f"  [bold cyan]Interface:  [/bold cyan]  {iface or 'default'}\n"
            f"  [bold cyan]Monitoring: [/bold cyan]  inbound TCP SYN / UDP / ICMP from external IPs",
            title="[bold bright_red]PEEKWATCH[/bold bright_red]",
            subtitle="[dim]Ctrl+C to stop and export report[/dim]",
            border_style="bright_red", box=box.ROUNDED,
        ))

        def _sniff():
            kwargs = {"prn": on_packet, "store": False}
            if iface:
                kwargs["iface"] = iface
            sniff(**kwargs)

        t = threading.Thread(target=_sniff, daemon=True)
        t.start()

        with Live(build_ui(), console=console, refresh_per_second=2, screen=True) as live:
            while True:
                time.sleep(0.5)
                live.update(build_ui())

    except KeyboardInterrupt:
        console.print("\n[dim]Monitoring stopped.[/dim]")
        if _total_alerts > 0:
            try:
                fname = export_session(iface)
                console.print(f"[green]Report saved:[/green]  {fname}")
            except Exception as ex:
                console.print(f"[yellow]Could not save report:[/yellow] {ex}")
        else:
            console.print("[dim]No external inbound traffic detected -- no report written.[/dim]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if _total_alerts > 0:
            try:
                fname = export_session(iface)
                console.print(f"[green]Report saved:[/green]  {fname}")
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()
