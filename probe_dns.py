#!/usr/bin/env python3
"""Probe: does DNS through the router fail after an idle gap?

  ./probe_dns.py live   # queries 1.1.1.1:53 (hijacked by the running router), gaps 2 s vs 13 s
  ./probe_dns.py lab [udp tcp https]   # GAPS=40:4,13:6 ./probe_dns.py lab https
                        # user-space sing-box on 127.0.0.1:15353 -> Throne SOCKS: udp vs tcp vs https DNS

Touches nothing: only DNS lookups of random names; `lab` runs an unprivileged sing-box
that connects to 127.0.0.1:2080 like any browser would.
"""
import json, os, random, socket, struct, subprocess, sys, tempfile, time

def query(host, port, name, timeout=4):
    """Return round-trip ms of an A query, or None on timeout / ICMP refusal."""
    q = struct.pack('>HHHHHH', random.randrange(65536), 0x100, 1, 0, 0, 0)
    q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0\0\1\0\1'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    t = time.monotonic()
    try:
        s.sendto(q, (host, port)); s.recv(512)
        return round((time.monotonic() - t) * 1000)
    except OSError:
        return None
    finally:
        s.close()

PLAN = tuple(tuple(map(int, g.split(':'))) for g in os.environ.get('GAPS', '2:4,13:6').split(','))

def gaps(host, port, plan=PLAN):
    for gap, n in plan:
        res = []
        for i in range(n):
            res.append(query(host, port, f'p{random.randrange(10**9)}.example.com'))
            print(f'  gap {gap:>2}s  #{i+1}: {"FAIL" if res[-1] is None else str(res[-1]) + " ms"}', flush=True)
            if i < n - 1: time.sleep(gap)
        print(f'  => gap {gap}s: {sum(r is None for r in res)}/{n} failed')

def live():
    print('live router, DNS hijacked from 1.1.1.1:53')
    since = time.strftime('%F %T')
    gaps('1.1.1.1', 53)
    log = subprocess.run(['journalctl', '-u', 'omarchy-router', '--since', since, '--no-pager'],
                         capture_output=True, text=True).stdout
    print(f'  journal since start: {log.count("process DNS packet")} "process DNS packet" errors')

def lab():
    for kind in sys.argv[2:] or ['udp', 'tcp', 'https']:
        server = {'type': kind, 'tag': 'dns', 'server': '1.1.1.1', 'detour': 'throne'}
        cfg = {'log': {'level': 'error'},
               'dns': {'servers': [server], 'strategy': 'ipv4_only'},
               'inbounds': [{'type': 'direct', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': 15353,
                             'override_address': '1.1.1.1', 'override_port': 53}],
               'outbounds': [{'type': 'socks', 'tag': 'throne', 'server': '127.0.0.1', 'server_port': 2080, 'version': '5'}],
               'route': {'rules': [{'inbound': ['in'], 'action': 'hijack-dns'}], 'final': 'throne'}}
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump(cfg, f)
        p = subprocess.Popen(['sing-box', 'run', '-c', f.name])
        time.sleep(1.5)
        if p.poll() is not None: sys.exit("sing-box did not start")
        print(f'\nlab: dns type={kind} via SOCKS 127.0.0.1:2080')
        try:
            gaps('127.0.0.1', 15353)
        finally:
            p.terminate(); p.wait(); os.unlink(f.name)

if __name__ == '__main__':
    {'live': live, 'lab': lab}[sys.argv[1] if len(sys.argv) > 1 else 'live']()
