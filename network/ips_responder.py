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

def block_ip(ip: str, reason: str = "MiniSOC Automated IPS Rule") -> dict:
    """
    Active defense: applies host firewall blocking rule for malicious remote IP.
    """
    if is_private_ip(ip):
        return {"success": False, "message": f"Skipped blocking private/loopback IP {ip}"}

    rule_name = f"MiniSOC_IPS_Block_{ip.replace(':', '_')}"
    system = platform.system()
    
    try:
        if system == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            # Also block outbound
            cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_out",
                "dir=out",
                "action=block",
                f"remoteip={ip}"
            ]
            subprocess.run(cmd_out, capture_output=True)
        else:
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, capture_output=True)

        # Store in database
        conn = get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_at, active)
            VALUES (?, ?, ?, 1)
        """, (ip, reason, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return {"success": True, "message": f"IP {ip} successfully blocked via firewall."}
    except Exception as e:
        return {"success": False, "message": f"Firewall execution failed: {str(e)}"}

def unblock_ip(ip: str) -> dict:
    rule_name = f"MiniSOC_IPS_Block_{ip.replace(':', '_')}"
    system = platform.system()
    try:
        if system == "Windows":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(cmd, capture_output=True)
            cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_out"]
            subprocess.run(cmd_out, capture_output=True)
        else:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)

        conn = get_conn()
        conn.execute("UPDATE blocked_ips SET active=0 WHERE ip_address=?", (ip,))
        conn.commit()
        conn.close()

        return {"success": True, "message": f"IP {ip} unblocked."}
    except Exception as e:
        return {"success": False, "message": f"Failed to unblock: {str(e)}"}

def list_blocked_ips():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
