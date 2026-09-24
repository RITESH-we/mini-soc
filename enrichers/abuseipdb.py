import requests
from network.ips_responder import is_public_routable_ip

BASE = 'https://api.abuseipdb.com/api/v2'

def lookup_ip(ip, api_key):
    if not ip or not is_public_routable_ip(ip):
        return {'score': 0, 'country': 'Private LAN', 'isp': 'RFC 1918 (Private Network)', 'totalReports': 0}
    if not api_key or 'YOUR' in api_key:
        return {'score': -1, 'country': '', 'isp': ''}
    try:
        r = requests.get(f'{BASE}/check',
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=10)
        if r.status_code == 200:
            d = r.json()['data']
            return {'score':   d.get('abuseConfidenceScore', 0),
                    'country': d.get('countryCode', ''),
                    'isp':     d.get('isp', ''),
                    'reports': d.get('totalReports', 0)}
    except Exception as e:
        return {'score': -1, 'error': str(e)}
    return {'score': 0}
