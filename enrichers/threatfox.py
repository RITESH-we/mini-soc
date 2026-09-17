import requests

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

def lookup_ioc(search_term: str) -> dict:
    """
    Queries abuse.ch ThreatFox for malicious IPs, domains, and payload hashes.
    Free, community-driven, no API key required.
    """
    if not search_term or len(search_term.strip()) == 0:
        return {"found": False, "threat_type": None, "malware_printable": None}

    payload = {
        "query": "search_ioc",
        "search_term": search_term.strip()
    }
    
    try:
        r = requests.post(THREATFOX_API, json=payload, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok" and data.get("data"):
                first_hit = data["data"][0]
                return {
                    "found": True,
                    "threat_type": first_hit.get("threat_type_desc"),
                    "malware_printable": first_hit.get("malware_printable"),
                    "confidence_level": first_hit.get("confidence_level"),
                    "tags": first_hit.get("tags") or [],
                    "reporter": first_hit.get("reporter")
                }
    except Exception as e:
        return {"found": False, "error": str(e)}

    return {"found": False}

def check_url(url: str) -> dict:
    """
    Queries abuse.ch URLhaus for malware payload URLs.
    """
    try:
        r = requests.post(URLHAUS_API, data={"url": url}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                return {
                    "threat": data.get("threat"),
                    "url_status": data.get("url_status"),
                    "tags": data.get("tags") or []
                }
    except Exception as e:
        return {"error": str(e)}
    return {"found": False}
