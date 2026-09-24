import platform
import subprocess
import ipaddress
from datetime import datetime
from database.models import get_conn

def is_public_routable_ip(ip: str) -> bool:
    """
    Returns True ONLY if ip is a valid, globally routable public IP.
    Strictly filters out RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8),
    link-local (169.254/16), carrier-grade NAT (100.64/10), multicast, broadcast, and invalid strings.
    """
    if not ip or not isinstance(ip, str):
        return False
    ip_clean = ip.strip()
    if not ip_clean or ip_clean in ('-', '127.0.0.1', 'localhost', '::1', '0.0.0.0'):
        return False
    # Strip port if present e.g. 192.168.1.1:4444 or [2001:db8::1]:80
    if ip_clean.startswith('[') and ']' in ip_clean:
        ip_clean = ip_clean[1:ip_clean.index(']')]
    elif ip_clean.count(':') == 1:
        parts = ip_clean.rsplit(':', 1)
        if parts[1].isdigit():
            ip_clean = parts[0]
    
    try:
        obj = ipaddress.ip_address(ip_clean)
        return bool(obj.is_global and not obj.is_multicast and not obj.is_reserved and not obj.is_loopback and not obj.is_link_local and not obj.is_unspecified)
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """Returns True if the IP is NOT globally routable (i.e. RFC 1918, loopback, or invalid)."""
    return not is_public_routable_ip(ip)

def get_hidden_subprocess_flags():
    flags = {}
    if platform.system() == "Windows":
        flags["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
            flags["startupinfo"] = si
        except Exception:
            pass
    return flags

import socket
import shutil

def resolve_target_to_ips(target: str) -> list:
    """
    Normalizes any input (IP address, URL like https://bad.com/path, or FQDN domain)
    into a list of valid IPv4 / IPv6 addresses.
    """
    if not target or not isinstance(target, str):
        return []
    clean = target.strip()
    if not clean:
        return []

    # Strip URL schemes, paths, queries
    if '://' in clean:
        clean = clean.split('://', 1)[1]
    if '/' in clean:
        clean = clean.split('/', 1)[0]
    if '?' in clean:
        clean = clean.split('?', 1)[0]
    if '#' in clean:
        clean = clean.split('#', 1)[0]

    # Strip port if present
    if clean.startswith('[') and ']' in clean:
        clean = clean[1:clean.index(']')]
    elif clean.count(':') == 1:
        parts = clean.rsplit(':', 1)
        if parts[1].isdigit():
            clean = parts[0]

    # If already a valid IP address
    try:
        ipaddress.ip_address(clean)
        return [clean]
    except ValueError:
        pass

    # Resolve hostname via DNS
    try:
        results = socket.getaddrinfo(clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips if ips else [clean]
    except Exception:
        return [clean]

def block_ip(ip: str, reason: str = "MiniSOC Automated IPS Rule", containment_profile: str = "BIDIRECTIONAL_DROP", target_endpoint: str = "GLOBAL") -> dict:
    """
    Active defense: applies host firewall blocking rule for malicious remote IP or domain.
    Supported containment profiles: 'BIDIRECTIONAL_DROP' (in+out), 'OUTBOUND_C2_DROP' (out only).
    Target endpoint: 'GLOBAL' (all fleet) or specific hostname (e.g. 'DESKTOP-ABC').
    """
    if not ip or not isinstance(ip, str):
        return {"success": False, "message": "Invalid or empty target specified."}

    raw_clean = ip.strip()
    if not raw_clean or raw_clean in ('-', '127.0.0.1', 'localhost', '::1', '0.0.0.0'):
        return {"success": False, "message": f"Skipped blocking loopback address {raw_clean}"}

    resolved_ips = resolve_target_to_ips(raw_clean)
    if not resolved_ips:
        return {"success": False, "message": f"Unable to resolve target '{raw_clean}' to a network address."}

    system = platform.system()
    flags = get_hidden_subprocess_flags()
    blocked_records = []
    target_endpoint = (target_endpoint or "GLOBAL").strip()

    for target_ip in resolved_ips:
        if target_ip in ('127.0.0.1', 'localhost', '::1', '0.0.0.0'):
            continue

        rule_name = f"MiniSOC_IPS_Block_{target_ip.replace(':', '_')}"

        # 1. Best-effort host firewall drop (does not fail if in container without CAP_NET_ADMIN)
        try:
            if system == "Windows":
                cmd_out = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_out",
                    "dir=out",
                    "action=block",
                    f"remoteip={target_ip}"
                ]
                subprocess.run(cmd_out, capture_output=True, **flags)

                if containment_profile == "BIDIRECTIONAL_DROP":
                    cmd_in = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={target_ip}"
                    ]
                    subprocess.run(cmd_in, capture_output=True, **flags)
            elif system == "Linux" and shutil.which("iptables"):
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"], capture_output=True)
                if containment_profile == "BIDIRECTIONAL_DROP":
                    subprocess.run(["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"], capture_output=True)
        except Exception:
            pass

        # 2. Store in database with target_endpoint scope
        target_reason = reason
        if raw_clean != target_ip:
            target_reason = f"{reason} (Target: {raw_clean})"

        conn = get_conn()
        try:
            conn.execute("""
                INSERT INTO blocked_ips (ip_address, reason, blocked_at, active, containment_profile, target_endpoint)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason=excluded.reason,
                    blocked_at=excluded.blocked_at,
                    active=1,
                    containment_profile=excluded.containment_profile,
                    target_endpoint=excluded.target_endpoint
            """, (target_ip, target_reason, datetime.now().isoformat(), containment_profile, target_endpoint))
            conn.commit()
            blocked_records.append(target_ip)
        finally:
            conn.close()

    return {
        "success": len(blocked_records) > 0,
        "message": f"Blocked {len(blocked_records)} target(s): {', '.join(blocked_records)} ({containment_profile}) on scope [{target_endpoint}].",
        "resolved_ips": blocked_records,
        "target_endpoint": target_endpoint
    }

def unblock_ip(ip: str, target_endpoint: str = None) -> dict:
    if not ip or not isinstance(ip, str):
        return {"success": False, "message": "Invalid target specified."}

    raw_clean = ip.strip()
    resolved_ips = resolve_target_to_ips(raw_clean)
    system = platform.system()
    flags = get_hidden_subprocess_flags()

    for target_ip in resolved_ips:
        rule_name = f"MiniSOC_IPS_Block_{target_ip.replace(':', '_')}"
        try:
            if system == "Windows":
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, **flags)
                cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_out"]
                subprocess.run(cmd_out, capture_output=True, **flags)
            elif system == "Linux" and shutil.which("iptables"):
                subprocess.run(["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"], capture_output=True)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", target_ip, "-j", "DROP"], capture_output=True)
        except Exception:
            pass

        conn = get_conn()
        try:
            conn.execute("UPDATE blocked_ips SET active=0 WHERE ip_address=?", (target_ip,))
            conn.commit()
        finally:
            conn.close()

    return {"success": True, "message": f"Target {raw_clean} unblocked.", "resolved_ips": resolved_ips}

def list_blocked_ips():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

