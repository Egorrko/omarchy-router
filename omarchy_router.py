#!/usr/bin/env python3
"""Per-app VPN bypass for Happ on Omarchy.

Own sing-box TUN sends chosen executables direct and everything else into Happ's
local SOCKS. An nftables guard drops any other internet egress, also while Happ
is closed or the VPN is down. `sudo omarchy_router.py install` sets it all up.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import time

import zapret

HERE = Path(__file__).resolve()
STATE = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'omarchy-router' / 'exceptions.json'
LAN = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
       '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
MARK = 21330        # 0x5352: sing-box marks its own sockets; the guard lets them out.
ZAPRET_MARK = 0x40000000  # zapret's nfqws marks the fakes and split segments it injects.
NFQWS_UID = 0x7FFFFFFF    # nfqws drops to this uid; its raw sockets must skip our TUN routing.
# Tailscale: tailscaled marks its own (WireGuard/DERP/STUN) sockets with 0x80000 in 0xff0000 and
# goes direct, so peers connect peer-to-peer. The tailnet itself rides tailscale0 and must not be
# captured by our TUN. Apps keep resolving through us (`tailscale set --accept-dns=false`, plain
# resolv.conf); only *.ts.net names go to MagicDNS, so other lookups do not leave the VPN.
TAILSCALE_MARK, TAILSCALE_MASK = 0x80000, 0xff0000
TAILSCALED = '/usr/bin/tailscaled'
TAILNET = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48']
MAGICDNS = '100.100.100.100'
ROUTER = 'omarchy-router.service'
GUARD = 'omarchy-router-guard.service'
BIN = Path('/usr/local/bin/omarchy-router')

GUARD_NFT = f'''destroy table inet omarchy-router
table inet omarchy-router {{
    chain egress {{
        type filter hook postrouting priority filter; policy drop;
        oifname "lo" accept
        oifname "orouter0" accept
        oifname "tailscale0" accept
        meta mark & {TAILSCALE_MASK} == {TAILSCALE_MARK} accept
        meta mark {MARK} accept
        meta mark & {ZAPRET_MARK} == {ZAPRET_MARK} counter accept
        ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }} accept
        ip6 daddr {{ fc00::/7, fe80::/10, ff00::/8 }} accept
        udp sport 68 udp dport 67 accept
        meta l4proto ipv6-icmp accept
    }}
}}
'''

GUARD_UNIT = f'''[Unit]
Description=Omarchy router guard: no internet outside VPN or exceptions
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f /etc/omarchy-router/guard.nft
ExecStop=/usr/bin/nft delete table inet omarchy-router

[Install]
WantedBy=multi-user.target
'''

ROUTER_UNIT = f'''[Unit]
Description=Omarchy router: per-app VPN bypass in front of Happ
Wants=network-online.target {GUARD}
After=network-online.target {GUARD}

[Service]
RuntimeDirectory=omarchy-router
ExecStartPre=/bin/sh -c '/usr/bin/python3 {BIN} export --state {{state}} > /run/omarchy-router/config.json'
ExecStart=/usr/bin/sing-box run -c /run/omarchy-router/config.json
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
'''

ZAPRET_UNIT = f'''[Unit]
Description=zapret (nfqws): DPI bypass for the router's direct exceptions
After=network-online.target {ROUTER}
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 {BIN} zapret-run --state {{state}}
ExecStopPost=/usr/bin/nft destroy table inet {zapret.TABLE}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
'''

SUDOERS = f'''{{user}} ALL=(root) NOPASSWD: /usr/bin/systemctl restart {ROUTER}, \\
    /usr/bin/systemctl start {GUARD} {ROUTER}, /usr/bin/systemctl stop {ROUTER} {GUARD}, \\
    /usr/bin/systemctl restart {zapret.SERVICE}, /usr/bin/systemctl start {zapret.SERVICE}, \\
    /usr/bin/systemctl stop {zapret.SERVICE}
'''


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f'Команда завершилась с ошибкой: {" ".join(args)}')
    return result


def validate(paths):
    if not isinstance(paths, list) or any(
        not isinstance(p, str) or not p.startswith('/')
        or any(ord(c) < 32 or ord(c) == 127 for c in p)
        for p in paths
    ):
        raise ValueError('Ожидался список абсолютных путей без управляющих символов')
    return sorted(set(paths))


def load(state=STATE):
    return validate([app(p) for p in json.loads(state.read_text())]) if state.exists() else []


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        try:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
            if os.geteuid() == 0:  # export at service start: leave a file the user can replace
                owner = path.parent.stat()
                os.chown(f.name, owner.st_uid, owner.st_gid)
            os.chmod(f.name, 0o644)
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


def rules_path(state):
    return state.with_name('rules.json')


def pattern(path):
    """'/x/' is a prefix (a Proton build); '*' stands for the rest of one path component."""
    body = ''.join('[^/]*' if c == '*' else re.escape(c) for c in path)
    return '^' + body + ('' if path.endswith('/') else '$')


def rule_set(paths):
    """sing-box reloads a local rule-set when the file changes, so applying exceptions does not
    restart the TUN and the network does not blink."""
    exact = [p for p in paths if not p.endswith('/') and '*' not in p]
    patterns = [pattern(p) for p in paths if p.endswith('/') or '*' in p]
    return {'version': 3, 'rules': ([{'process_path': exact}] if exact else [])
                                   + ([{'process_path_regex': patterns}] if patterns else [])}


def save(paths, state=STATE):
    paths = validate(paths)
    write(state, paths)
    write(rules_path(state), rule_set(paths))


WINE = {'wineserver', 'wine-preloader', 'wine64-preloader', 'wine', 'wine64'}


def app(path):
    """Every Wine game is the same wine64-preloader and wineserver, so the exception is the
    whole Proton/Wine build under $HOME (a prefix ending in '/'), not one executable."""
    match = re.match(r'(/home/[^/]+/.+?)/(files|bin|lib\d*)/', path)
    if match and Path(path).name in WINE:
        return match[1] + '/'
    # An AppImage runs from /tmp/.mount_<6 chars of its name><6 random chars>/, new on every start;
    # Discord-style self-updaters move to a new app-<version>/ directory on every update.
    path = re.sub(r'^(/tmp/\.mount_[^/]{6})[^/]{6}/', r'\1*/', path)
    return re.sub(r'/app-\d+(\.\d+)+/', '/app-*/', path)


def processes():
    paths = set()
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            path = os.readlink(proc / 'exe')
            if not path.endswith(' (deleted)'):
                paths.update(validate([app(path)]))
        except (OSError, ValueError):
            continue
    return sorted(paths, key=lambda p: (Path(p).name.casefold(), p))


# Row in the Omarchy menu (Setup → Network); the shell hot-reloads the file.
MENU_ENTRY = ('"setup.network.vpn": {"icon":"\U000f0582","label":"VPN",'
              f'"action":"{BIN} open","checked":"systemctl is-active -q {GUARD}"}},')
WEB = 'omarchy-router-web.service'
WEB_UNIT = f'''[Unit]
Description=omarchy-router control page on http://127.0.0.1:{{port}}

[Service]
ExecStart=/usr/bin/python3 {HERE.parent / 'web.py'}
Restart=on-failure

[Install]
WantedBy=default.target
'''


def open_page():
    import web
    subprocess.run(['systemctl', '--user', 'start', WEB], check=True)
    for _ in range(30):  # the server needs a moment after a cold start
        if subprocess.run(['ss', '-Hltn', f'sport = :{web.PORT}'], capture_output=True,
                          text=True).stdout.strip():
            break
        time.sleep(.1)
    subprocess.run(['omarchy-launch-webapp', f'http://127.0.0.1:{web.PORT}/'])


def config(rules_file, port=10808, core='/opt/happ/bin/core/xray', dns='1.1.1.1', dns_type='https',
           core_dns='77.88.8.8'):
    core = validate([core])
    if not 1 <= port <= 65535:
        raise ValueError('Недопустимый порт SOCKS')
    rules = [{'port': 53, 'action': 'hijack-dns'},  # DNAT'd by auto_redirect; must precede the LAN rule
             {'process_path': core, 'outbound': 'direct'},
             {'process_path': [TAILSCALED], 'outbound': 'direct'},
             {'ip_cidr': LAN, 'outbound': 'direct'},
             {'rule_set': 'exceptions', 'outbound': 'direct'}]
    exceptions = {'type': 'local', 'tag': 'exceptions', 'format': 'source', 'path': str(rules_file)}
    return {
        'log': {'level': 'info'},
        # Hijacked plain DNS goes through the VPN: direct 1.1.1.1:53 is censored on this network.
        # While the VPN is down, exceptions only reach hosts they have already resolved.
        # https, not udp/tcp: Throne hijacked port 53 itself and dropped the session after 10 s idle,
        # so the next query hit a dead relay and timed out (~6% of lookups). DoH is never hijacked.
        # ipv4_only: this host has no direct IPv6, and Wine games take the VPN's AAAA answer
        # and never fall back to A; the empty AAAA reply makes them use IPv4.
        # The core's own lookups (the VPN server's name) must not ride the VPN it is bringing up:
        # hijack-dns catches them first, and with Happ's TUN off they looped back into xray (2026-09-23).
        'dns': {'servers': [{'type': dns_type, 'tag': 'dns', 'server': dns, 'detour': 'vpn'},
                            {'type': 'udp', 'tag': 'core-dns', 'server': core_dns},
                            {'type': 'udp', 'tag': 'tailnet', 'server': MAGICDNS,
                             'bind_interface': 'tailscale0'}],  # auto_detect_interface would pin enp5s0
                'rules': [{'process_path': core, 'server': 'core-dns'},
                          {'domain_suffix': ['ts.net'], 'server': 'tailnet'}],
                'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'tun', 'tag': 'apps', 'interface_name': 'orouter0',
                      'address': ['172.31.255.1/30', 'fd4f:6d61:7263::1/126'],
                      'auto_route': True, 'auto_redirect': True, 'exclude_uid': [NFQWS_UID],
                      'auto_redirect_output_mark': MARK,
                      'route_exclude_address': TAILNET,
                      'strict_route': True, 'stack': 'mixed'}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'},
                      {'type': 'socks', 'tag': 'vpn', 'server': '127.0.0.1',
                       'server_port': port, 'version': '5'}],
        'route': {'auto_detect_interface': True, 'default_domain_resolver': 'core-dns',
                  'rule_set': [exceptions], 'rules': rules, 'final': 'vpn'},
    }


def choose(title, rows):
    """rows are 'label' or 'label\\tsubtext'; the menu shows a glyph and returns the row."""
    result = subprocess.run(['omarchy', 'menu', 'select', title, *(f'\t{row}' for row in rows)],
                            text=True, capture_output=True)
    if result.returncode == 1:
        return None
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Не удалось открыть меню Omarchy')
    selected = result.stdout.rstrip('\n')
    if selected not in rows:
        raise ValueError('Неизвестный ответ меню')
    return selected


def systemctl(*args):
    run('sudo', '-n', 'systemctl', *args)


def active():
    return subprocess.run(['systemctl', 'is-active', '-q', ROUTER]).returncode == 0


def off():
    if choose('Разрешить весь интернет напрямую, без VPN?', ['Да, отключить защиту', 'Нет']) == 'Да, отключить защиту':
        systemctl('stop', ROUTER, GUARD)


def menu(state):
    paths = load(state)
    while True:
        protection = 'Отключить защиту…' if active() else 'Включить защиту'
        action = choose(f'VPN: защита {"включена" if active() else "выключена"} · исключений: {len(paths)}',
                        ['Добавить приложение', 'Удалить исключение', 'Сохранить и применить',
                         protection, 'Выйти без сохранения'])
        if action in (None, 'Выйти без сохранения'):
            return
        if action == 'Сохранить и применить':
            save(paths, state)  # the running sing-box reloads rules.json by itself
            return
        if action == 'Включить защиту':
            systemctl('start', GUARD, ROUTER)
            continue
        if action == 'Отключить защиту…':
            off()
            continue
        candidates = [p for p in processes() if p not in paths] if action == 'Добавить приложение' else paths
        if not candidates:
            choose('Список пуст', ['Назад'])
            continue
        # Exact executable paths keep Steam and its games separate; no PID persistence.
        rows = {f'{Path(p).name}\t{p}': p for p in candidates}
        selected = choose(action, list(rows))
        if selected:
            path = rows[selected]
            paths = sorted(set(paths) | {path}) if action == 'Добавить приложение' else [p for p in paths if p != path]


def install():
    user = os.environ.get('SUDO_USER')
    if os.geteuid() or not user:
        raise RuntimeError('Запускать так: sudo ./omarchy_router.py install')
    if subprocess.run(['ip', 'link', 'show', 'happ-xray'], capture_output=True).returncode == 0:
        raise RuntimeError('В Happ включён режим TUN. Выключи его (Advanced settings → TUN), оставив '
                           'только локальный прокси 127.0.0.1:10808, и повтори установку.')
    run('pacman', '-S', '--needed', '--noconfirm', 'sing-box')
    home = Path(pwd.getpwnam(user).pw_dir)
    state = home / '.config' / 'omarchy-router' / 'exceptions.json'
    files = {Path('/etc/omarchy-router/guard.nft'): GUARD_NFT,
             Path('/etc/systemd/system') / GUARD: GUARD_UNIT,
             Path('/etc/systemd/system') / ROUTER: ROUTER_UNIT.format(state=state),
             Path('/etc/systemd/system') / zapret.SERVICE: ZAPRET_UNIT.format(state=state)}
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    # Same filesystem for os.replace; a dot in the name keeps sudo from reading the draft.
    with tempfile.NamedTemporaryFile('w', dir='/etc/sudoers.d', prefix='.draft.', delete=False) as f:
        f.write(SUDOERS.format(user=user))
    try:
        run('visudo', '-c', '-q', '-f', f.name)
        os.chmod(f.name, 0o440)
        os.replace(f.name, '/etc/sudoers.d/omarchy-router')
    finally:
        Path(f.name).unlink(missing_ok=True)
    BIN.unlink(missing_ok=True)
    BIN.symlink_to(HERE)
    menu_file = home / '.config' / 'omarchy' / 'extensions' / 'omarchy-menu.jsonc'
    text = menu_file.read_text() if menu_file.exists() else '{\n}\n'
    if MENU_ENTRY not in text:  # the stock file already ends with a trailing comma
        text = ''.join(l for l in text.splitlines(True) if '"setup.network.vpn"' not in l)
        head, _, tail = text.rpartition('}')
        menu_file.write_text(f'{head}  {MENU_ENTRY}\n}}{tail}')
        os.chown(menu_file, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', GUARD, ROUTER)
    run('systemctl', 'start', GUARD)
    run('nft', '-f', '/etc/omarchy-router/guard.nft')  # atomic reload when the guard was already up
    run('systemctl', 'restart', ROUTER)
    # Our zapret replaces zapret-rust: its queue rule has no `bypass`, so a stopped or hung nfqws
    # dropped every new connection on the uplink, the VPN's own included, and its teardown left
    # the rules behind. Stop it and remove its table before ours starts.
    subprocess.run(['systemctl', 'disable', '--now', 'zapret-rust.service'], capture_output=True)
    subprocess.run(['pkill', '-9', '-f', 'zapret-rust-linux'], capture_output=True)
    subprocess.run(['pkill', '-x', 'nfqws'], capture_output=True)
    subprocess.run(['nft', 'destroy', 'table', 'inet', 'zapret'], capture_output=True)
    subprocess.run(['nft', 'destroy', 'table', 'ip', 'zapret_nat'], capture_output=True)
    run('systemctl', 'enable', zapret.SERVICE)
    run('systemctl', 'restart', zapret.SERVICE)
    import web
    unit = home / '.config' / 'systemd' / 'user' / WEB
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(WEB_UNIT.format(port=web.PORT))
    for path in (unit, unit.parent):
        os.chown(path, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
    subprocess.run(['systemctl', '--user', f'--machine={user}@', 'daemon-reload'], capture_output=True)
    subprocess.run(['systemctl', '--user', f'--machine={user}@', 'enable', WEB], capture_output=True)
    subprocess.run(['systemctl', '--user', f'--machine={user}@', 'restart', WEB], capture_output=True)
    print(f'Готово: защита включена, панель — `{BIN.name} open` (http://127.0.0.1:{web.PORT}/), '
          f'аварийно — `{BIN.name} off`.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['menu', 'off', 'list', 'export', 'install',
                                            'open', 'zapret-run', 'zapret-tune', 'zapret-check'])
    parser.add_argument('--state', type=Path, default=STATE)
    parser.add_argument('--port', type=int, default=10808)
    args = parser.parse_args()
    if args.command == 'open':
        open_page()
    elif args.command == 'zapret-run':
        zapret.run(args.state)
    elif args.command == 'zapret-tune':
        best, score = zapret.tune(args.state, progress=lambda p: print(
            f'{p["index"]}/{p["total"]} {p["strategy"]}: {p["ok"]}/{p["of"]}', flush=True))
        print(f'Выбрана {best}: {score}/{len(zapret.CHECKS)}')
    elif args.command == 'zapret-check':
        print(json.dumps(zapret.check(), indent=2))
    elif args.command == 'menu':
        menu(args.state)
    elif args.command == 'off':
        off()
    elif args.command == 'install':
        install()
    else:
        if args.command == 'list':
            data = processes()
        else:  # ExecStartPre: rules.json follows exceptions.json even if it was edited by hand
            write(rules_path(args.state), rule_set(load(args.state)))
            data = config(rules_path(args.state), args.port)
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        if os.geteuid():  # the menu runs without a terminal; root runs in one
            subprocess.run(['notify-send', '-u', 'critical', 'VPN', str(error)], stderr=subprocess.DEVNULL)
        raise SystemExit(str(error))
