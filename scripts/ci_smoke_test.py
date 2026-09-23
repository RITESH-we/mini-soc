import sys, os, traceback, json

sys.path.insert(0, os.getcwd())

import importlib.util
spec = importlib.util.spec_from_file_location('app', 'dashboard/app.py')
mod = importlib.util.module_from_spec(spec)
sys.modules['app'] = mod

try:
    spec.loader.exec_module(mod)
    print('[+] Module loaded OK')

    app = mod.app
    app.config['TESTING'] = True

    with app.test_client() as client:
        r = client.get('/health')
        print(f'/health -> {r.status_code}')
        assert r.status_code == 200

        r = client.get('/login')
        print(f'/login -> {r.status_code}')
        assert r.status_code == 200

        r = client.get('/api/live/metrics')
        print(f'/api/live/metrics -> {r.status_code}')
        assert r.status_code == 401
        data = json.loads(r.data)
        flag = data.get('session_expired')
        print(f'  session_expired flag: {flag}')
        assert flag is True

        r = client.post('/login',
                        data={'username': 'admin', 'password': 'minisoc@admin', 'next': '/'},
                        follow_redirects=False)
        print(f'POST /login -> {r.status_code}')
        assert r.status_code in (302, 200)

    print()
    print('ALL SMOKE TESTS PASSED')

except Exception as e:
    traceback.print_exc()
    sys.exit(1)
