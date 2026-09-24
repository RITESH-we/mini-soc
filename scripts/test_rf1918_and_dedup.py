import sys
import os
import json
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

print("=" * 65)
print("MiniSOC RFC 1918 Guard & False Positive / De-duplication Test Suite")
print("=" * 65)

# ── Test 1: RFC 1918 and Globally Routable IP Verification ─────
print("\n[1] Testing is_public_routable_ip & is_private_ip guards...")
from network.ips_responder import is_public_routable_ip, is_private_ip

private_test_cases = [
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.168.1.100:8080",
    "127.0.0.1",
    "127.0.0.1:5000",
    "localhost",
    "169.254.1.1",       # Link-local
    "100.64.0.1",        # Shared address space / CGNAT
    "224.0.0.1",         # Multicast
    "255.255.255.255",   # Broadcast
    "::1",               # IPv6 Loopback
    "fe80::1",           # IPv6 Link-local
    "",
    "-",
    None,
]

public_test_cases = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "142.250.190.46:443",
    "2606:4700:4700::1111",
]

for ip in private_test_cases:
    is_pub = is_public_routable_ip(ip)
    assert not is_pub, f"FAIL: Expected private/non-routable for '{ip}', got is_public={is_pub}"
    assert is_private_ip(ip) is True, f"FAIL: is_private_ip should return True for '{ip}'"

print("  [+] All RFC 1918 / Private / Loopback / CGNAT test cases correctly identified.")

for ip in public_test_cases:
    is_pub = is_public_routable_ip(ip)
    assert is_pub, f"FAIL: Expected public/routable for '{ip}', got is_public={is_pub}"
    assert is_private_ip(ip) is False, f"FAIL: is_private_ip should return False for '{ip}'"

print("  [+] All public globally-routable IPs correctly identified.")

# ── Test 2: CTI Enrichers RFC 1918 Guard ───────────────────────
print("\n[2] Testing CTI Enrichers Pre-Flight RFC 1918 Checks...")
from enrichers.virustotal import lookup_ip as vt_lookup
from enrichers.abuseipdb import lookup_ip as abuse_lookup
from enrichers.otx import lookup_ip as otx_lookup
from enrichers.threatfox import lookup_ioc as tf_lookup

# Ensure no external HTTP requests are made for internal IPs
vt_res = vt_lookup("192.168.1.50", api_key="test_dummy_key")
assert "RFC 1918" in vt_res.get("score", ""), f"VT failed RFC1918 check: {vt_res}"

abuse_res = abuse_lookup("10.0.0.5", api_key="test_dummy_key")
assert abuse_res.get("score") == 0 and "RFC 1918" in abuse_res.get("isp", ""), f"AbuseIPDB failed RFC1918 check: {abuse_res}"

otx_res = otx_lookup("172.16.1.1", api_key="test_dummy_key")
assert "RFC1918" in otx_res.get("tags", []), f"OTX failed RFC1918 check: {otx_res}"

tf_res = tf_lookup("127.0.0.1:4444")
assert tf_res.get("found") is False and "RFC 1918" in tf_res.get("threat_type", ""), f"ThreatFox failed RFC1918 check: {tf_res}"

print("  [+] PASS: All 4 CTI enrichers completely block external lookups on private IPs.")

# ── Test 3: Alert De-duplication Engine ────────────────────────
print("\n[3] Testing Alert De-duplication Engine (Sliding Window)...")
from database.models import get_conn, init_db
from dashboard.app import create_or_deduplicate_alert

init_db()
conn = get_conn()

rule = "Test C2 Beaconing Rule"
hostname = "TEST-WORKSTATION-01"
proc = "PID:9999"
ip = "198.51.100.22"

# Clean up any leftover test alerts
conn.execute("DELETE FROM alerts WHERE device_name=? AND rule_name=?", (hostname, rule))
conn.commit()

now = datetime.now().isoformat()


# 1st occurrence: Should create a new alert
aid1 = create_or_deduplicate_alert(
    conn=conn,
    now_iso=now,
    sev="HIGH",
    rname=rule,
    description="Test connection to port 4444",
    src_ip=ip,
    src_user="testuser",
    device_name=hostname,
    process=proc,
    event_id=9002,
    threat_category="EXFILTRATION",
    dedup_window_minutes=15
)
conn.commit()

row1 = conn.execute("SELECT occurrence_count, description FROM alerts WHERE id=?", (aid1,)).fetchone()
assert row1["occurrence_count"] == 1, f"Expected occurrence_count 1, got {row1['occurrence_count']}"

# 2nd occurrence 20 seconds later: Should consolidate into the SAME alert ID!
now2 = datetime.now().isoformat()
aid2 = create_or_deduplicate_alert(
    conn=conn,
    now_iso=now2,
    sev="HIGH",
    rname=rule,
    description="Test connection to port 4444",
    src_ip=ip,
    src_user="testuser",
    device_name=hostname,
    process=proc,
    event_id=9002,
    threat_category="EXFILTRATION",
    dedup_window_minutes=15
)
conn.commit()

assert aid1 == aid2, f"FAIL: De-duplication did not return identical alert ID! aid1={aid1}, aid2={aid2}"

row2 = conn.execute("SELECT occurrence_count, description, last_seen FROM alerts WHERE id=?", (aid1,)).fetchone()
assert row2["occurrence_count"] == 2, f"Expected occurrence_count 2, got {row2['occurrence_count']}"
assert "[Repeated 2x]" in row2["description"], f"Expected '[Repeated 2x]' in description, got: {row2['description']}"
assert row2["last_seen"] == now2, f"Expected last_seen updated to now2"

print(f"  [+] Alert #{aid1} successfully de-duplicated from 1x to {row2['occurrence_count']}x occurrences.")
conn.close()

print("\n" + "=" * 65)
print("[+] ALL RFC 1918 & ALERT DE-DUPLICATION TESTS PASSED SUCCESSFULLY!")
print("=" * 65)
