import sys, os, traceback, json, platform

print(f"Python: {sys.version}")
print(f"Platform: {platform.system()} {platform.release()}")
print(f"CWD: {os.getcwd()}")
print(f"app.py exists: {os.path.exists('dashboard/app.py')}")
print(f"config.yaml exists: {os.path.exists('config.yaml')}")
print(f"minisoc.db exists: {os.path.exists('minisoc.db')}")
print()

sys.path.insert(0, os.getcwd())

import importlib.util
spec = importlib.util.spec_from_file_location('app', 'dashboard/app.py')
mod = importlib.util.module_from_spec(spec)
sys.modules['app'] = mod

try:
    print("[*] Loading dashboard/app.py ...")
    spec.loader.exec_module(mod)
    print('[+] Module loaded OK')

    app = mod.app
    app.config['TESTING'] = True

    with app.test_client() as client:
        r = client.get('/health')
        print(f'/health -> {r.status_code}')
        assert r.status_code == 200, f'/health returned {r.status_code}, body: {r.data[:200]}'

        r = client.get('/login')
        print(f'/login -> {r.status_code}')
        assert r.status_code == 200, f'/login returned {r.status_code}'

        r = client.get('/api/live/metrics')
        print(f'/api/live/metrics -> {r.status_code}')
        assert r.status_code == 401, f'/api/live/metrics returned {r.status_code} (expected 401)'
        data = json.loads(r.data)
        flag = data.get('session_expired')
        print(f'  session_expired flag: {flag}')
        assert flag is True, f'session_expired flag missing, got: {data}'

        r = client.post('/login',
                        data={'username': 'admin', 'password': 'minisoc@admin', 'next': '/'},
                        follow_redirects=False)
        print(f'POST /login -> {r.status_code}')
        assert r.status_code in (302, 200), f'login POST returned {r.status_code}, body: {r.data[:200]}'

    print()
    print('ALL SMOKE TESTS PASSED')

except Exception as e:
    print(f'\nFATAL ERROR: {e}')
    traceback.print_exc()
    sys.exit(1)
