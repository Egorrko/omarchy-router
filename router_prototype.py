#!/usr/bin/env python3
"""Technical prototype: select executables and export an independent TUN config.

Does not install services, change Throne, or activate a firewall.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

STATE = Path(__file__).resolve().parent / '.prototype' / 'exceptions.json'
LAN = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
       '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
MARK = 21330


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


def processes():
    paths = set()
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            path = os.readlink(proc / 'exe')
            if not path.endswith(' (deleted)'):
                paths.update(validate([path]))
        except (OSError, ValueError):
            continue
    return sorted(paths, key=lambda p: (Path(p).name.casefold(), p))


def config(paths, port=2080, core='/opt/Throne/ThroneCore'):
    paths = validate(paths)
    if not 1 <= port <= 65535:
        raise ValueError('Недопустимый порт SOCKS')
    rules = [{'process_path': validate([core]), 'outbound': 'direct'},
             {'ip_cidr': LAN, 'outbound': 'direct'}]
    if paths:
        rules.append({'process_path': paths, 'outbound': 'direct'})
    return {
        'log': {'level': 'info'},
        'inbounds': [{'type': 'tun', 'tag': 'apps', 'interface_name': 'orouter0',
                      'address': ['172.31.255.1/30', 'fdfe:dcba:9876::1/126'],
                      'auto_route': True, 'auto_redirect': True,
                      'auto_redirect_output_mark': MARK,
                      'strict_route': True, 'stack': 'mixed'}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'},
                      {'type': 'socks', 'tag': 'throne', 'server': '127.0.0.1',
                       'server_port': port, 'version': '5'}],
        'route': {'auto_detect_interface': True,
                  'rules': rules, 'final': 'throne'},
    }


def choose(title, rows):
    result = subprocess.run(['omarchy', 'menu', 'select', title, *rows],
                            text=True, capture_output=True)
    if result.returncode == 1:
        return None
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Не удалось открыть меню Omarchy')
    selected = result.stdout.rstrip('\n')
    if selected not in rows:
        raise ValueError('Неизвестный ответ меню')
    return selected


def menu(state):
    paths = load(state)
    while True:
        action = choose(f'VPN — прототип, защита не включена · исключений: {len(paths)}',
                        ['Добавить приложение', 'Удалить исключение',
                         'Сохранить список', 'Выйти без сохранения'])
        if action in (None, 'Выйти без сохранения'):
            return
        if action == 'Сохранить список':
            save(paths, state)
            print(f'Список сохранён: {state}. Сетевые настройки не применялись.')
            return
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['menu', 'list', 'export'])
    parser.add_argument('--state', type=Path, default=STATE)
    parser.add_argument('--port', type=int, default=2080)
    args = parser.parse_args()
    if args.command == 'menu':
        menu(args.state)
    else:
        data = processes() if args.command == 'list' else config(load(args.state), args.port)
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error))
