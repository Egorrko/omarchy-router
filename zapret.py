"""zapret (nfqws) beside the router: DPI bypass for the exceptions' direct traffic.

The Flowseal strategies (zapret-discord-youtube-linux/*.bat) are winws command lines; they are
translated to nfqws arguments plus the ports to queue. The nftables table is ours, not
zapret-rust's: its queue rule has the `bypass` flag, so a dead or restarting nfqws lets packets
through untouched instead of dropping every new connection (the VPN's own included).
"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
STRATEGIES = HERE / 'zapret-discord-youtube-linux'
NFQWS = HERE / 'bin' / 'nfqws'
SERVICE = 'omarchy-zapret.service'
TABLE = 'omarchy-zapret'
QUEUE = 200
MARK = 0x40000000          # nfqws marks what it injects; never queue those again
TAILSCALE = (0x80000, 0xff0000)
GAME_PORTS = '1024-65535'
NO_GAME_PORTS = '12'       # Flowseal's placeholder when the game filter is off
CURL_DIRECT = Path.home() / '.local' / 'bin' / 'curl-direct'
# What "Discord works" means for the tuner: TLS through to these hosts on the direct path.
CHECKS = ['https://discord.com/api/v9/gateway', 'https://gateway.discord.gg',
          'https://cdn.discordapp.com', 'https://media.discordapp.net', 'https://updates.discord.com']


def state_path(state):
    return state.with_name('zapret.json')


def strategies():
    return sorted((p.name for p in STRATEGIES.glob('general*.bat')),
                  key=lambda n: [int(t) if t.isdigit() else t.casefold() for t in re.split(r'(\d+)', n)])


def load(state):
    data = {'strategy': 'general (ALT9).bat', 'game_filter': True}
    path = state_path(state)
    if path.exists():
        data.update(json.loads(path.read_text()))
    if data['strategy'] not in strategies():
        raise ValueError(f'Нет стратегии {data["strategy"]}')
    return data


def parse(name, game_filter=True):
    """winws command line of a Flowseal .bat → (tcp ports, udp ports, nfqws args)."""
    text = (STRATEGIES / name).read_text(encoding='utf-8', errors='replace').replace('\r', '')
    text = re.sub(r'\^\n', ' ', text)
    line = next(l for l in text.splitlines() if 'winws.exe"' in l)
    games = GAME_PORTS if game_filter else NO_GAME_PORTS
    for var, value in [('%BIN%', 'bin/'), ('%LISTS%', 'lists/'), ('%GameFilterTCP%', games),
                       ('%GameFilterUDP%', games), ('%GameFilter%', games)]:
        line = line.replace(var, value)
    args = shlex.split(line.split('winws.exe"', 1)[1])
    tcp, udp, rest = [], [], []
    for arg in args:
        if arg.startswith('--wf-tcp='):
            tcp += arg.split('=', 1)[1].split(',')
        elif arg.startswith('--wf-udp='):
            udp += arg.split('=', 1)[1].split(',')
        else:
            rest.append(arg)
    if not rest:
        raise ValueError(f'{name}: не нашёл аргументов winws')
    return merge(tcp), merge(udp), rest


def merge(ports):
    """'80', '1024-65535', '443' → non-overlapping nft set elements (nft refuses overlaps)."""
    spans = []
    for p in ports:
        if not p:
            continue
        a, _, b = p.partition('-')
        spans.append((int(a), int(b or a)))
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return [str(a) if a == b else f'{a}-{b}' for a, b in out]


def uplink():
    routes = json.loads(subprocess.run(['ip', '-j', 'route', 'show', 'default', 'table', 'main'],
                                       text=True, capture_output=True, check=True).stdout)
    if not routes:
        raise RuntimeError('Нет маршрута по умолчанию в main')
    return routes[0]['dev']


def nft(tcp, udp, iface):
    def rule(proto, ports):
        return (f'        oifname "{iface}" meta mark & {MARK:#x} == 0 '
                f'meta mark & {TAILSCALE[1]:#x} != {TAILSCALE[0]:#x} '
                f'{proto} dport {{ {", ".join(ports)} }} ct original packets 1-6 '
                f'counter queue flags bypass to {QUEUE}\n')
    return (f'destroy table inet {TABLE}\ntable inet {TABLE} {{\n'
            f'    chain post {{\n        type filter hook postrouting priority mangle; policy accept;\n'
            + (rule('tcp', tcp) if tcp else '') + (rule('udp', udp) if udp else '')
            + '    }\n}\n')


def run(state):
    """ExecStart of the service (root): our queue rules, then exec nfqws in the strategy dir."""
    data = load(state)
    tcp, udp, args = parse(data['strategy'], data['game_filter'])
    subprocess.run(['nft', '-f', '-'], input=nft(tcp, udp, uplink()), text=True, check=True)
    os.chdir(STRATEGIES)
    print(f'zapret: {data["strategy"]}, game filter {"on" if data["game_filter"] else "off"}', flush=True)
    os.execv(NFQWS, [str(NFQWS), f'--qnum={QUEUE}', f'--dpi-desync-fwmark={MARK:#x}', *args])


def check(timeout=5):
    """Hosts from CHECKS that complete TLS on the direct path; run in parallel."""
    procs = {url: subprocess.Popen([str(CURL_DIRECT), '-s', '-o', '/dev/null', '-m', str(timeout), url],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for url in CHECKS}
    return {url: p.wait() == 0 for url, p in procs.items()}


def restart():
    subprocess.run(['sudo', '-n', 'systemctl', 'restart', SERVICE], check=True,
                   capture_output=True, text=True)


def active():
    return subprocess.run(['systemctl', 'is-active', '-q', SERVICE]).returncode == 0


def tune(state, progress=print, names=None):
    """Try strategies until one opens every Discord host; keep the best one found."""
    data = load(state)
    original = data['strategy']
    best, best_score = original, -1
    names = names or [original] + [n for n in strategies() if n != original]  # keep a working one
    for i, name in enumerate(names, 1):
        save(state, strategy=name)
        restart()
        time.sleep(1.5)
        result = check()
        score = sum(result.values())
        progress({'index': i, 'total': len(names), 'strategy': name,
                  'ok': score, 'of': len(result)})
        if score > best_score:
            best, best_score = name, score
        if score == len(result):
            break
    save(state, strategy=best)
    restart()
    return best, best_score


def save(state, **changes):
    data = load(state)
    data.update(changes)
    if data['strategy'] not in strategies():
        raise ValueError(f'Нет стратегии {data["strategy"]}')
    path = state_path(state)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    os.replace(tmp, path)
    return data
