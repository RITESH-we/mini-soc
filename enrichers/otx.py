import requests

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

def lookup_indicator(indicator_type: str, indicator: str, api_key: str = None) -> dict:
    """
    indicator_type: 'IPv4', 'domain', 'file'
    """
    if not indicator:
        return {"pulse_count": 0, "tags": [], "malicious": False}
        
    headers = {"X-OTX-API-KEY": api_key} if api_key and "YOUR" not in api_key else {}
    url = f"{BASE_URL}/{indicator_type}/{indicator}/general"
    
    try:
        r = requests.get(url, headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            pulse_info = data.get("pulse_info", {})
            count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])
            tags = set()
            for p in pulses[:5]:
                for t in p.get("tags", []):
                    tags.add(t)
            return {
                "pulse_count": count,
                "tags": list(tags)[:6],
                "malicious": count > 0,
                "reputation": data.get("reputation", 0)
            }
    except Exception as e:
        return {"pulse_count": 0, "tags": [], "error": str(e), "malicious": False}
        
    return {"pulse_count": 0, "tags": [], "malicious": False}

from network.ips_responder import is_public_routable_ip

def lookup_ip(ip: str, api_key: str = None) -> dict:
    if not ip or not is_public_routable_ip(ip):
        return {
            "pulse_count": 0,
            "tags": ["RFC1918", "Private"],
            "malicious": False,
            "reputation": 0
        }
    return lookup_indicator("IPv4", ip, api_key)

def lookup_hash(file_hash: str, api_key: str = None) -> dict:
    return lookup_indicator("file", file_hash, api_key)

