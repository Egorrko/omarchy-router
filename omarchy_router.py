#!/usr/bin/env python3
"""Per-app VPN bypass for Throne on Omarchy.

Own sing-box TUN sends chosen executables direct and everything else into Throne's
local SOCKS. An nftables guard drops any other internet egress, also while Throne
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

HERE = Path(__file__).resolve()
STATE = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'omarchy-router' / 'exceptions.json'
LAN = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
       '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
MARK = 21330        # 0x5352: sing-box marks its own sockets; the guard lets them out.
THRONE_MARK = 8228  # 0x2024: mark Throne's core may put on its sockets.
ZAPRET_MARK = 0x40000000  # zapret's nfqws marks the fakes and split segments it injects.
NFQWS_UID = 0x7FFFFFFF    # nfqws drops to this uid; its raw sockets must skip our TUN routing.
ROUTER = 'omarchy-router.service'
GUARD = 'omarchy-router-guard.service'
BIN = Path('/usr/local/bin/omarchy-router')

GUARD_NFT = f'''destroy table inet omarchy-router
table inet omarchy-router {{
    chain egress {{
        type filter hook postrouting priority filter; policy drop;
        oifname "lo" accept
        oifname "orouter0" accept
        meta mark {{ {MARK}, {THRONE_MARK} }} accept
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
Description=Omarchy router: per-app VPN bypass in front of Throne
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

SUDOERS = f'''{{user}} ALL=(root) NOPASSWD: /usr/bin/systemctl restart {ROUTER}, \\
    /usr/bin/systemctl start {GUARD} {ROUTER}, /usr/bin/systemctl stop {ROUTER} {GUARD}
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
    return validate(json.loads(state.read_text())) if state.exists() else []


def save(paths, state=STATE):
    paths = validate(paths)
    state.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=state.parent, delete=False) as f:
        try:
            json.dump(paths, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
            os.replace(f.name, state)
        finally:
            Path(f.name).unlink(missing_ok=True)


WINE = {'wineserver', 'wine-preloader', 'wine64-preloader', 'wine', 'wine64'}


def app(path):
    """Every Wine game is the same wine64-preloader and wineserver, so the exception is the
    whole Proton/Wine build under $HOME (a prefix ending in '/'), not one executable."""
    match = re.match(r'(/home/[^/]+/.+?)/(files|bin|lib\d*)/', path)
    return match[1] + '/' if match and Path(path).name in WINE else path


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
MENU_ENTRY = ('"setup.network.vpn": {"icon":"\U000f0582","label":"VPN exceptions",'
              f'"action":"{BIN} menu","checked":"systemctl is-active -q {GUARD}"}},')


def config(paths, port=2080, core='/opt/Throne/ThroneCore', dns='1.1.1.1'):
    paths = validate(paths)
    if not 1 <= port <= 65535:
        raise ValueError('Недопустимый порт SOCKS')
    rules = [{'port': 53, 'action': 'hijack-dns'},  # DNAT'd by auto_redirect; must precede the LAN rule
             {'process_path': validate([core]), 'outbound': 'direct'},
             {'ip_cidr': LAN, 'outbound': 'direct'}]
    if exact := [p for p in paths if not p.endswith('/')]:
        rules.append({'process_path': exact, 'outbound': 'direct'})
    if builds := [p for p in paths if p.endswith('/')]:
        rules.append({'process_path_regex': ['^' + re.escape(p) for p in builds], 'outbound': 'direct'})
    return {
        'log': {'level': 'info'},
        # Hijacked plain DNS goes through the VPN: direct 1.1.1.1:53 is censored on this network.
        # While the VPN is down, exceptions only reach hosts they have already resolved.
        # ipv4_only: this host has no direct IPv6, and Wine games take the VPN's AAAA answer
        # and never fall back to A; the empty AAAA reply makes them use IPv4.
        'dns': {'servers': [{'type': 'udp', 'tag': 'dns', 'server': dns, 'detour': 'throne'}],
                'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'tun', 'tag': 'apps', 'interface_name': 'orouter0',
                      'address': ['172.31.255.1/30', 'fd4f:6d61:7263::1/126'],
                      'auto_route': True, 'auto_redirect': True, 'exclude_uid': [NFQWS_UID],
                      'auto_redirect_output_mark': MARK,
                      'strict_route': True, 'stack': 'mixed'}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'},
                      {'type': 'socks', 'tag': 'throne', 'server': '127.0.0.1',
                       'server_port': port, 'version': '5'}],
        'route': {'auto_detect_interface': True,
                  'rules': rules, 'final': 'throne'},
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
            save(paths, state)
            systemctl('restart', ROUTER)
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
    if subprocess.run(['ip', 'link', 'show', 'throne-tun'], capture_output=True).returncode == 0:
        raise RuntimeError('В Throne включён режим TUN. Выключи его, оставив только локальный прокси '
                           '127.0.0.1:2080, и повтори установку.')
    run('pacman', '-S', '--needed', '--noconfirm', 'sing-box')
    home = Path(pwd.getpwnam(user).pw_dir)
    state = home / '.config' / 'omarchy-router' / 'exceptions.json'
    files = {Path('/etc/omarchy-router/guard.nft'): GUARD_NFT,
             Path('/etc/systemd/system') / GUARD: GUARD_UNIT,
             Path('/etc/systemd/system') / ROUTER: ROUTER_UNIT.format(state=state)}
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
        head, _, tail = text.rpartition('}')
        menu_file.write_text(f'{head}  {MENU_ENTRY}\n}}{tail}')
        os.chown(menu_file, pwd.getpwnam(user).pw_uid, pwd.getpwnam(user).pw_gid)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', GUARD, ROUTER)
    run('systemctl', 'start', GUARD)
    run('nft', '-f', '/etc/omarchy-router/guard.nft')  # atomic reload when the guard was already up
    run('systemctl', 'restart', ROUTER)
    print(f'Готово: защита включена, меню — `{BIN.name} menu`, аварийно — `{BIN.name} off`.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['menu', 'off', 'list', 'export', 'install'])
    parser.add_argument('--state', type=Path, default=STATE)
    parser.add_argument('--port', type=int, default=2080)
    args = parser.parse_args()
    if args.command == 'menu':
        menu(args.state)
    elif args.command == 'off':
        off()
    elif args.command == 'install':
        install()
    else:
        data = processes() if args.command == 'list' else config(load(args.state), args.port)
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        if os.geteuid():  # the menu runs without a terminal; root runs in one
            subprocess.run(['notify-send', '-u', 'critical', 'VPN', str(error)], stderr=subprocess.DEVNULL)
        raise SystemExit(str(error))
