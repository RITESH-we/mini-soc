import time, yaml, sys
from colorama import init, Fore, Style

init(autoreset=True)

with open('config.yaml') as f:
    config = yaml.safe_load(f)

from database.models import get_conn, init_db
from collectors.windows_events import collect_all
from detectors.rule_engine import evaluate

init_db()

SEV_COLOR = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH':     Fore.YELLOW + Style.BRIGHT,
    'MEDIUM':   Fore.CYAN,
    'LOW':      Fore.GREEN,
}

def save_alert(alert):
    conn = get_conn()
    conn.execute(
        'INSERT INTO alerts '
        '(timestamp,severity,rule_name,description,src_ip,src_user,'
        'process,event_id,mitre_tactic,mitre_technique,raw_event,status) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        (alert['timestamp'], alert['severity'], alert['rule_name'],
         alert['description'], alert['src_ip'], alert['src_user'],
         alert['process'], alert['event_id'], alert['mitre_tactic'],
         alert['mitre_technique'], alert['raw_event'], 'OPEN')
    )
    conn.commit()
    conn.close()

def run():
    print(Fore.BLUE + Style.BRIGHT + '=' * 52)
    print(Fore.BLUE + Style.BRIGHT + '  MiniSOC - SOC L1 Platform  |  by rites')
    print(Fore.BLUE + Style.BRIGHT + '=' * 52)
    print(f'  Dashboard -> http://{config["dashboard"]["host"]}:{config["dashboard"]["port"]}')
    print('  Monitoring Windows Event Logs... (Ctrl+C to stop)\n')

    seen = set()
    while True:
        try:
            for event in collect_all():
                key = (f"{event['event_id']}_"
                       f"{event['timestamp']}_"
                       f"{(event.get('strings') or [''])[0][:30]}")
                if key in seen:
                    continue
                seen.add(key)
                alert = evaluate(event, config)
                if alert:
                    save_alert(alert)
                    color = SEV_COLOR.get(alert['severity'], '')
                    print(f"{color}[{alert['severity']:8s}] "
                          f"{alert['rule_name']:35s} | "
                          f"{alert['mitre_technique']:12s} | "
                          f"{alert['timestamp'][:19]}")
            time.sleep(5)
        except KeyboardInterrupt:
            print('\n  MiniSOC stopped.')
            break
        except Exception as e:
            print(f'[ERROR] {e}')
            time.sleep(10)

if __name__ == '__main__':
    run()
