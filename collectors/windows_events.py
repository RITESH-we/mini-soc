import win32evtlog
from datetime import datetime

WATCHED = {
    'Security': [4624, 4625, 4648, 4688, 4698, 4720, 4732],
    'Microsoft-Windows-Sysmon/Operational': [1, 3, 7, 10, 11, 13, 22],
    'Microsoft-Windows-PowerShell/Operational': [4104],
}

def read_events(log_name, event_ids, max_events=200):
    events = []
    try:
        hand  = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raws  = win32evtlog.ReadEventLog(hand, flags, 0)
        count = 0
        while raws and count < max_events:
            for ev in raws:
                eid = ev.EventID & 0xFFFF
                if eid in event_ids:
                    events.append({
                        'log':       log_name,
                        'event_id':  eid,
                        'timestamp': str(ev.TimeGenerated),
                        'source':    ev.SourceName,
                        'strings':   list(ev.StringInserts or []),
                    })
                    count += 1
            raws = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f'[COLLECTOR] {log_name}: {e}')
    return events

def collect_all():
    all_events = []
    for log, ids in WATCHED.items():
        all_events.extend(read_events(log, ids))
    return all_events
