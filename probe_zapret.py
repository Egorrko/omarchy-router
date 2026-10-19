#!/usr/bin/env python3
"""Probe: do zapret and the router get in each other's way?

  sudo ./probe_zapret.py    # once with zapret running, once with it stopped; compare

Two phases. VPN: requests via the default path (TUN -> Happ); zapret should not touch them.
Exceptions: TLS with sing-box's own mark, i.e. exactly the path an exception takes; zapret
should make its hostlist sites work there. The guard counts packets that nfqws injects
(mark 0x40000000): injections during the VPN phase mean zapret is mangling the VPN link.
Read-only: changes nothing, only sends requests.
"""
import json, os, socket, ssl, statistics, subprocess, time

MARK = 21330
VPN_URLS = ['https://www.google.com/generate_204', 'https://www.youtube.com/', 'https://discord.com/']
# discord.com in list-general, youtube in list-google; example.com is the control: works without zapret
EXCEPTION_HOSTS = ['example.com', 'discord.com', 'www.youtube.com', 'rutracker.org']
TRIES = 5


def counters():
    """(packets zapret queued, packets nfqws injected and the guard let out)"""
    def rules(table):
        out = subprocess.run(['nft', '-j', 'list', 'table', 'inet', table], capture_output=True, text=True).stdout
        return [i['rule'] for i in json.loads(out or '{"nftables": []}')['nftables'] if 'rule' in i]
    def packets(rule):
        return sum(e['counter']['packets'] for e in rule['expr'] if 'counter' in e)
    queued = sum(packets(r) for r in rules('zapret') if r['chain'] == 'zapret_post')
    injected = sum(packets(r) for r in rules('omarchy-router'))  # the only counter there is the zapret-mark rule
    return queued, injected


def vpn(url):
    r = subprocess.run(['curl', '-sS', '-m', '8', '-o', '/dev/null', '-w', '%{http_code} %{time_total}', url],
                       capture_output=True, text=True)
    code, t = (r.stdout.split() + ['000', '0'])[:2]
    return code not in ('000', ''), float(t) * 1000, r.stderr.strip()[:80]


def exception(host):
    t = time.monotonic()
    try:
        out = subprocess.run(['timeout', '4', 'getent', 'ahostsv4', host], capture_output=True, text=True).stdout
        if not out:
            raise OSError('no DNS answer')
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, 36, MARK)  # SO_MARK: skip our TUN, like sing-box's direct outbound
        s.settimeout(6)
        s.connect((out.split()[0], 443))
        with ssl.create_default_context().wrap_socket(s, server_hostname=host) as tls:
            tls.sendall(f'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            tls.recv(64)
        return True, (time.monotonic() - t) * 1000, ''
    except Exception as e:
        return False, (time.monotonic() - t) * 1000, f'{type(e).__name__}: {e}'[:80]


def phase(name, targets, probe):
    print(f'== {name}')
    before = counters()
    for target in targets:
        results = [probe(target) for _ in range(TRIES)]
        ok = [ms for good, ms, _ in results if good]
        errors = {err for good, _, err in results if not good}
        median = f'{statistics.median(ok):6.0f} ms' if ok else '     —   '
        print(f'  {target:<40} {len(ok)}/{TRIES} ok  {median}  {"; ".join(errors)}')
    after = counters()
    print(f'  zapret queued {after[0] - before[0]} packets, nfqws injected {after[1] - before[1]}')
    return after[1] - before[1]


if __name__ == '__main__':
    if os.geteuid():
        raise SystemExit('run with sudo')
    running = subprocess.run(['pgrep', '-x', 'nfqws'], capture_output=True).returncode == 0
    print(f'{time.strftime("%F %T")}  zapret: {"RUNNING" if running else "stopped"}  (run again with it '
          f'{"stopped" if running else "running"} and compare)\n')
    vpn_injected = phase('VPN path (TUN -> Happ): zapret must not touch it', VPN_URLS, vpn)
    phase('exception path (direct): zapret should help its hostlist sites', EXCEPTION_HOSTS, exception)
    if running:
        print('\nVPN phase:', 'nfqws injected packets into VPN traffic (or a game was running): CONFLICT'
              if vpn_injected else 'no injections: zapret leaves the VPN alone')
