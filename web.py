"""Local control page for omarchy-router: exceptions, zapret, health and repair.

Runs as the user (systemd --user), listens on 127.0.0.1 only. Every API call needs the per-start
token embedded in the page and a loopback Host header, so another site open in the browser can
neither drive it (custom header → CORS preflight, refused) nor reach it by DNS rebinding.
Privileged steps go through the same sudoers whitelist as the menu.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import subprocess
import threading
import time

import omarchy_router as router
import zapret

PORT = 7377
TOKEN = secrets.token_urlsafe(24)
PAGE = Path(__file__).resolve().parent / 'web.html'
HOSTS = {f'127.0.0.1:{PORT}', f'localhost:{PORT}'}
STATE = router.STATE
LOCK = threading.Lock()   # one writer at a time for exceptions / zapret state
TUNE = {'running': False, 'log': [], 'result': None, 'error': None}


def is_active(unit):
    return subprocess.run(['systemctl', 'is-active', '-q', unit]).returncode == 0


def sudo_systemctl(*args):
    result = subprocess.run(['sudo', '-n', 'systemctl', *args], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f'systemctl {" ".join(args)} не удалось')


def probe(argv, timeout=6):
    started = time.monotonic()
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout + 2)
        ok = result.returncode == 0
        out = result.stdout.strip()
    except subprocess.TimeoutExpired:
        ok, out = False, ''
    return {'ok': ok, 'ms': round((time.monotonic() - started) * 1000), 'detail': out[:80]}


def health():
    """Each layer on its own, so a failure names the layer instead of 'no internet'."""
    curl = ['curl', '-s', '-m', '6']
    direct = str(zapret.CURL_DIRECT)
    checks = {}
    threads = {  # 'direct' goes out as an exception: proves the uplink without the VPN
        'direct': lambda: probe([direct, '-s', '-m', '6', 'https://ipinfo.io/ip']),
        'happ': lambda: probe(curl + ['--socks5-hostname', '127.0.0.1:10808', 'https://ipinfo.io/ip']),
        'vpn': lambda: probe(curl + ['https://ipinfo.io/ip']),
        'discord': lambda: zapret.check(),
        'tailscale': tailscale,
    }
    def work(name, fn):
        checks[name] = fn()
    pool = [threading.Thread(target=work, args=item) for item in threads.items()]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    discord = checks['discord']
    checks['discord'] = {'ok': all(discord.values()), 'hosts': discord,
                         'detail': f'{sum(discord.values())}/{len(discord)}'}
    return checks


def tailscale():
    try:
        out = subprocess.run(['tailscale', 'status', '--json'], text=True, capture_output=True,
                             timeout=5).stdout
        data = json.loads(out)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'ok': False, 'detail': 'не установлен или не запущен'}
    peers = (data.get('Peer') or {}).values()
    return {'ok': data.get('BackendState') == 'Running',
            'detail': f'{sum(p.get("Online", False) for p in peers)} из {len(peers)} устройств онлайн'}


def status():
    paths = router.load(STATE)
    z = zapret.load(STATE)
    return {
        'guard': is_active(router.GUARD), 'router': is_active(router.ROUTER),
        'zapret': is_active(zapret.SERVICE),
        'strategy': z['strategy'], 'game_filter': z['game_filter'], 'strategies': zapret.strategies(),
        'exceptions': [{'path': p, 'name': name(p)} for p in paths],
        'tune': TUNE,
    }


def name(path):
    return Path(path.rstrip('/')).name.replace('*', '')


def processes():
    current = set(router.load(STATE))
    return [{'path': p, 'name': name(p)} for p in router.processes() if p not in current]


def set_exceptions(change):
    with LOCK:
        paths = router.load(STATE)
        router.save(change(paths), STATE)   # sing-box reloads rules.json itself: no blink


def tune_job():
    try:
        TUNE.update(running=True, log=[], result=None, error=None)
        with LOCK:
            best, score = zapret.tune(STATE, progress=TUNE['log'].append)
        TUNE['result'] = {'strategy': best, 'ok': score, 'of': len(zapret.CHECKS)}
    except Exception as error:  # surfaced on the page
        TUNE['error'] = str(error)
    finally:
        TUNE['running'] = False


def repair():
    """Restart only what is down, in dependency order, and say what was done."""
    steps = []
    if not is_active(router.GUARD) or not is_active(router.ROUTER):
        sudo_systemctl('start', router.GUARD, router.ROUTER)
        steps.append('Защита и роутер были выключены — запустил')
        time.sleep(3)
    h = health()
    if not h['direct']['ok']:
        steps.append('Нет прямого интернета: проблема у провайдера, Wi-Fi или кабеля — роутер тут ни при чём')
        return {'steps': steps, 'health': h}
    if not h['happ']['ok']:
        steps.append('Happ не отвечает на 127.0.0.1:10808: открой Happ и нажми «Подключить» '
                     '(после обновления Happ — см. AGENTS.md про версию 4.3)')
    elif not h['vpn']['ok']:
        sudo_systemctl('restart', router.ROUTER)
        steps.append('Happ работает, а роутер нет — перезапустил роутер')
        time.sleep(3)
    if not h['discord']['ok']:
        sudo_systemctl('restart', zapret.SERVICE)
        time.sleep(2)
        if all(zapret.check().values()):
            steps.append('Discord не открывался — перезапустил zapret, заработало')
        else:
            steps.append('Discord не открывается и после перезапуска zapret — запусти «Подобрать стратегию»')
    if not steps:
        steps.append('Всё работает, чинить нечего')
    return {'steps': steps, 'health': health()}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, kind='application/json; charset=utf-8'):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def allowed(self, api=True):
        if self.headers.get('Host') not in HOSTS:
            self.send(403, {'error': 'bad host'})
            return False
        if api and not secrets.compare_digest(self.headers.get('X-Token', ''), TOKEN):
            self.send(403, {'error': 'bad token'})
            return False
        return True

    def do_GET(self):
        if self.path == '/':
            if self.allowed(api=False):
                html = PAGE.read_text().replace('__TOKEN__', TOKEN)
                self.send(200, html.encode(), 'text/html; charset=utf-8')
            return
        if not self.allowed():
            return
        routes = {'/api/status': status, '/api/processes': processes, '/api/health': health}
        if self.path not in routes:
            return self.send(404, {'error': 'not found'})
        self.respond(routes[self.path])

    def do_POST(self):
        if not self.allowed():
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length) or b'{}') if length < 65536 else {}
        def add():
            path = router.validate([body['path']])[0]
            set_exceptions(lambda paths: paths + [router.app(path)])
            return status()
        def remove():
            set_exceptions(lambda paths: [p for p in paths if p != body['path']])
            return status()
        def strategy():
            with LOCK:
                zapret.save(STATE, **{k: body[k] for k in ('strategy', 'game_filter') if k in body})
            sudo_systemctl('restart', zapret.SERVICE)
            return status()
        def zapret_action():
            action = body.get('action')
            if action not in ('start', 'stop', 'restart'):
                raise ValueError('bad action')
            sudo_systemctl(action, zapret.SERVICE)
            return status()
        def protection():
            if body.get('on'):
                sudo_systemctl('start', router.GUARD, router.ROUTER)
            else:
                sudo_systemctl('stop', router.ROUTER, router.GUARD)
            return status()
        def tune():
            if not TUNE['running']:
                TUNE['running'] = True
                threading.Thread(target=tune_job, daemon=True).start()
            return status()
        routes = {'/api/exceptions/add': add, '/api/exceptions/remove': remove,
                  '/api/zapret/strategy': strategy, '/api/zapret': zapret_action,
                  '/api/protection': protection, '/api/zapret/tune': tune, '/api/repair': repair}
        if self.path not in routes:
            return self.send(404, {'error': 'not found'})
        self.respond(routes[self.path])

    def respond(self, fn):
        try:
            self.send(200, fn())
        except Exception as error:
            self.send(500, {'error': str(error)})


def main():
    server = ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == '__main__':
    main()
