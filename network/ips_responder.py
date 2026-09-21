import platform
import subprocess
import ipaddress
from datetime import datetime
from database.models import get_conn

def is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback
    except ValueError:
        return True

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

def block_ip(ip: str, reason: str = "MiniSOC Automated IPS Rule", containment_profile: str = "BIDIRECTIONAL_DROP") -> dict:
    """
    Active defense: applies host firewall blocking rule for malicious remote IP.
    Supported containment profiles: 'BIDIRECTIONAL_DROP' (in+out), 'OUTBOUND_C2_DROP' (out only).
    """
    if is_private_ip(ip):
        return {"success": False, "message": f"Skipped blocking private/loopback IP {ip}"}

    rule_name = f"MiniSOC_IPS_Block_{ip.replace(':', '_')}"
    system = platform.system()
    flags = get_hidden_subprocess_flags()
    
    try:
        if system == "Windows":
            # Always block outbound to stop C2 beacons / data exfiltration
            cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_out",
                "dir=out",
                "action=block",
                f"remoteip={ip}"
            ]
            subprocess.run(cmd_out, capture_output=True, **flags)

            # Block inbound if BIDIRECTIONAL_DROP
            if containment_profile == "BIDIRECTIONAL_DROP":
                cmd_in = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}"
                ]
                subprocess.run(cmd_in, capture_output=True, **flags)
        else:
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True)
            if containment_profile == "BIDIRECTIONAL_DROP":
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)

        # Store in database
        conn = get_conn()
        try:
            conn.execute("""
                INSERT INTO blocked_ips (ip_address, reason, blocked_at, active, containment_profile)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason=excluded.reason,
                    blocked_at=excluded.blocked_at,
                    active=1,
                    containment_profile=excluded.containment_profile
            """, (ip, reason, datetime.now().isoformat(), containment_profile))
            conn.commit()
        finally:
            conn.close()

        return {"success": True, "message": f"IP {ip} blocked ({containment_profile}).", "rule": rule_name}
    except Exception as e:
        return {"success": False, "message": f"Failed to block: {str(e)}"}

def unblock_ip(ip: str) -> dict:
    rule_name = f"MiniSOC_IPS_Block_{ip.replace(':', '_')}"
    system = platform.system()
    flags = get_hidden_subprocess_flags()
    try:
        if system == "Windows":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(cmd, capture_output=True, **flags)
            cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_out"]
            subprocess.run(cmd_out, capture_output=True, **flags)
        else:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)

        conn = get_conn()
        try:
            conn.execute("UPDATE blocked_ips SET active=0 WHERE ip_address=?", (ip,))
            conn.commit()
        finally:
            conn.close()

        return {"success": True, "message": f"IP {ip} unblocked."}
    except Exception as e:
        return {"success": False, "message": f"Failed to unblock: {str(e)}"}

def list_blocked_ips():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
