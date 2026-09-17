from datetime import datetime
from collections import defaultdict

_failed_logins = defaultdict(list)

def evaluate(event, config):
    eid = event.get('event_id')
    if   eid == 4625: return _brute_force(event, config)
    elif eid == 4648: return _pass_the_hash(event)
    elif eid == 4698: return _scheduled_task(event)
    elif eid == 4720: return _new_user(event)
    elif eid == 4732: return _added_to_admin(event)
    elif eid == 1:    return _suspicious_process(event)
    elif eid == 10:   return _lsass_access(event)
    return None

def _alert(rule, sev, desc, event, tactic, tech, ip='', user='', proc=''):
    return {
        'timestamp':       datetime.now().isoformat(),
        'rule_name':       rule,
        'severity':        sev,
        'description':     desc,
        'event_id':        event.get('event_id'),
        'mitre_tactic':    tactic,
        'mitre_technique': tech,
        'src_ip':          ip,
        'src_user':        user,
        'process':         proc,
        'raw_event':       str(event),
        'status':          'OPEN',
    }

def _brute_force(event, config):
    s    = event.get('strings', [])
    user = s[5]  if len(s) > 5  else 'unknown'
    ip   = s[19] if len(s) > 19 else ''
    now  = datetime.now()
    th   = config.get('detection', {}).get('brute_force_threshold', 5)
    win  = config.get('detection', {}).get('brute_force_window_sec', 60)
    _failed_logins[user].append(now)
    _failed_logins[user] = [t for t in _failed_logins[user] if (now - t).seconds <= win]
    if len(_failed_logins[user]) >= th:
        _failed_logins[user] = []
        return _alert('Brute Force Login', 'HIGH',
            f'{th} failed logins for {user} in {win}s',
            event, 'Credential Access', 'T1110', ip=ip, user=user)
    return None

def _pass_the_hash(event):
    s    = event.get('strings', [])
    user = s[5]  if len(s) > 5  else 'unknown'
    ip   = s[18] if len(s) > 18 else ''
    return _alert('Pass-the-Hash', 'HIGH',
        f'Explicit credential use for {user} - possible PtH',
        event, 'Lateral Movement', 'T1550.002', ip=ip, user=user)

def _scheduled_task(event):
    s    = event.get('strings', [])
    task = s[0] if s else 'unknown'
    return _alert('Scheduled Task Created', 'MEDIUM',
        f'New scheduled task: {task}',
        event, 'Persistence', 'T1053.005', proc=task)

def _new_user(event):
    s    = event.get('strings', [])
    user = s[0] if s else 'unknown'
    return _alert('New Local User Created', 'MEDIUM',
        f'User account created: {user}',
        event, 'Persistence', 'T1136.001', user=user)

def _added_to_admin(event):
    s     = event.get('strings', [])
    user  = s[0] if s else 'unknown'
    group = s[2] if len(s) > 2 else 'Administrators'
    if 'admin' in group.lower():
        return _alert('User Added to Admin Group', 'HIGH',
            f'{user} added to {group}',
            event, 'Privilege Escalation', 'T1078.003', user=user)
    return None

def _suspicious_process(event):
    s      = event.get('strings', [])
    image  = s[4].lower()  if len(s) > 4  else ''
    parent = s[20].lower() if len(s) > 20 else ''
    bad_p  = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mshta.exe']
    bad_c  = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe']
    if any(p in parent for p in bad_p) and any(c in image for c in bad_c):
        return _alert('Suspicious Child Process', 'CRITICAL',
            f'Office app spawned shell {image} - possible phishing',
            event, 'Execution', 'T1059', proc=image)
    return None

def _lsass_access(event):
    s      = event.get('strings', [])
    target = s[4].lower() if len(s) > 4 else ''
    source = s[0].lower() if s else ''
    if 'lsass' in target:
        return _alert('LSASS Access Detected', 'CRITICAL',
            f'{source} accessed LSASS - credential dumping suspected',
            event, 'Credential Access', 'T1003.001', proc=source)
    return None
