import requests

BASE = 'https://www.virustotal.com/api/v3'

def lookup_ip(ip, api_key):
    if not ip or not api_key or 'YOUR' in api_key:
        return {'score': 'N/A', 'country': ''}
    try:
        r = requests.get(f'{BASE}/ip_addresses/{ip}',
            headers={'x-apikey': api_key}, timeout=10)
        if r.status_code == 200:
            attr  = r.json()['data']['attributes']
            stats = attr.get('last_analysis_stats', {})
            mal   = stats.get('malicious', 0)
            total = sum(stats.values())
            return {'score':   f'{mal}/{total}',
                    'country': attr.get('country', ''),
                    'tags':    attr.get('tags', [])}
    except Exception as e:
        return {'score': f'error:{e}'}
    return {'score': '0/0'}

def lookup_hash(h, api_key):
    if not h or not api_key or 'YOUR' in api_key:
        return {'score': 'N/A', 'name': ''}
    try:
        r = requests.get(f'{BASE}/files/{h}',
            headers={'x-apikey': api_key}, timeout=10)
        if r.status_code == 200:
            attr  = r.json()['data']['attributes']
            stats = attr.get('last_analysis_stats', {})
            mal   = stats.get('malicious', 0)
            total = sum(stats.values())
            return {'score': f'{mal}/{total}',
                    'name':  attr.get('meaningful_name', '')}
    except Exception as e:
        return {'score': f'error:{e}'}
    return {'score': '0/0'}
