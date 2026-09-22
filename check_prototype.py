#!/usr/bin/env python3
"""Run with python check_prototype.py /absolute/path/to/sing-box (1.13.x); after install: /usr/bin/sing-box.

All network and firewall changes happen in a disposable user/network namespace.
Uses real TCP/UDP connections, TUN and two distinct executable paths.
"""
import json
import re
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from omarchy_router import GUARD_NFT, MARK, app, config, load, save, validate

HERE = Path(__file__).resolve()


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')
    return result


SERVER = '''
import socket, threading, time
def serve(family, kind, address):
    s = socket.socket(family, kind)
    if family == socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((address, 18080))
    if kind == socket.SOCK_STREAM:
        s.listen()
        while True:
            c, peer = s.accept()
            c.sendall(peer[0].encode()); c.close()
    else:
        while True:
            _, peer = s.recvfrom(100)
            s.sendto(peer[0].encode(), peer)
# A wildcard UDP socket would reply from the interface address (198.18.0.2), and the
# client's connected socket would drop it; bind the fake "internet" addresses instead.
for f, tcp, udp in [(socket.AF_INET, '0.0.0.0', '203.0.113.2'), (socket.AF_INET6, '::', '2001:db8:2::2')]:
    threading.Thread(target=serve, args=(f, socket.SOCK_STREAM, tcp), daemon=True).start()
    threading.Thread(target=serve, args=(f, socket.SOCK_DGRAM, udp), daemon=True).start()
def dns():  # answers any single-question query with A 203.0.113.53
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('203.0.113.2', 53))
    while True:
        q, peer = s.recvfrom(512)
        s.sendto(q[:2] + b'\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00' + q[12:]
                 + b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04' + socket.inet_aton('203.0.113.53'), peer)
threading.Thread(target=dns, daemon=True).start()
time.sleep(300)
'''

CLIENT = '''
import socket, sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,
                socket.SOCK_DGRAM if sys.argv[2] in ('udp', 'dns') else socket.SOCK_STREAM)
s.settimeout(1.5)
if sys.argv[2]=='dns':  # A? "x." to a public address: hijacked by the router's DNS
    s.connect((sys.argv[1],53))
    s.send(b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x01x\\x00\\x00\\x01\\x00\\x01')
    print(socket.inet_ntoa(s.recv(512)[-4:])); sys.exit()
s.connect((sys.argv[1],18080))
if sys.argv[2]=='udp': s.send(b'ping')
print(s.recv(100).decode())
'''


def wait_port(port, process):
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError('sing-box exited; see log below')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('Listener did not start')


def isolated(binary):
    assert os.readlink('/proc/self/ns/net') != os.environ['PROTOTYPE_HOST_NETNS']
    children = []
    with tempfile.TemporaryDirectory(prefix='router-check-') as directory:
        tmp = Path(directory)
        logs = open(tmp / 'core.log', 'w+')
        try:
            state = tmp / 'exceptions.json'
            save(['/games/dota 2/dota2', '/games/dota 2/dota2'], state)
            assert load(state) == ['/games/dota 2/dota2']
            proton = '/home/u/Steam/steamapps/common/Proton - Experimental/'
            assert app(proton + 'files/bin/wineserver') == app(proton + 'files/lib/wine/i386-unix/wine64-preloader') == proton
            assert app('/usr/lib/wine/x86_64-unix/wine64-preloader') == '/usr/lib/wine/x86_64-unix/wine64-preloader'
            assert app(proton + 'files/bin/python3') == proton + 'files/bin/python3'
            assert {'process_path_regex': ['^' + re.escape(proton)], 'outbound': 'direct'} in config([proton])['route']['rules']
            for bad in [['relative'], ['/bad\npath'], 'not a list']:
                try:
                    validate(bad)
                except ValueError:
                    pass
                else:
                    raise AssertionError('Invalid state accepted')
            direct = str(tmp / 'direct-python')
            shutil.copy2(sys.executable, direct)
            core = str(tmp / 'core-python')  # stands in for xray: only its DNS is special
            shutil.copy2(sys.executable, core)
            proxy_binary = str(tmp / 'throne-fixture')
            shutil.copy2(binary, proxy_binary)
            # Holds the "internet" namespace. The server starts only after addresses exist:
            # a UDP socket bound while lo is still down replies from the interface address.
            internet = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'], stdout=logs, stderr=logs)
            children.append(internet)
            for _ in range(100):
                if os.readlink(f'/proc/{internet.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                    break
                time.sleep(.01)
            # Host gets rp_filter=2 per interface from systemd-sysctl via udev; a fresh netns
            # keeps the strict default and drops TUN replies. Mirror the host.
            run('sysctl', '-q', 'net.ipv4.conf.all.rp_filter=2', 'net.ipv4.conf.default.rp_filter=2')
            # No IPv6 duplicate address detection: addresses are usable immediately, no timing races.
            for prefix in ([], ['nsenter', '-t', str(internet.pid), '-n']):
                run(*prefix, 'sysctl', '-q', 'net.ipv6.conf.all.accept_dad=0', 'net.ipv6.conf.default.accept_dad=0')
            run('ip', 'link', 'set', 'lo', 'up')
            run('ip', 'link', 'add', 'wan0', 'type', 'veth', 'peer', 'name', 'peer0')
            run('ip', 'link', 'set', 'peer0', 'netns', str(internet.pid))
            remote = ['nsenter', '-t', str(internet.pid), '-n', 'ip']
            run(*remote, 'link', 'set', 'lo', 'up')
            run(*remote, 'link', 'set', 'peer0', 'up')
            run('ip', 'link', 'set', 'wan0', 'up')
            for address in ['198.18.0.1/24', '198.18.0.3/24', '10.25.0.1/24', '2001:db8:1::1/64']:
                run('ip', 'addr', 'add', address, 'dev', 'wan0')
            # Proxy-only source address: deprecated, so plain sockets never pick it on their own.
            run('ip', 'addr', 'add', '2001:db8:1::3/64', 'dev', 'wan0', 'preferred_lft', '0')
            for address in ['198.18.0.2/24', '10.25.0.2/24', '2001:db8:1::2/64']:
                run(*remote, 'addr', 'add', address, 'dev', 'peer0')
            for address in ['203.0.113.2/32', '2001:db8:2::2/128']:
                run(*remote, 'addr', 'add', address, 'dev', 'lo')
            run('ip', 'route', 'add', 'default', 'via', '198.18.0.2')
            run('ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:1::2')
            time.sleep(.3)
            server = subprocess.Popen(['nsenter', '-t', str(internet.pid), '-n', sys.executable, '-c', SERVER],
                                      stdout=logs, stderr=logs)
            children.append(server)
            for _ in range(100):
                if run(*remote[:-1], 'ss', '-Hltn', 'sport', '=', '18080').stdout.count('\n') == 2:
                    break
                time.sleep(.05)

            def start(executable, document, name):
                path = tmp / (name + '.json')
                path.write_text(json.dumps(document))
                run(executable, 'check', '-c', str(path))
                process = subprocess.Popen([executable, 'run', '-c', str(path)], stdout=logs, stderr=logs)
                children.append(process)
                return process

            proxy = start(proxy_binary, {
                'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': 10808}],
                'outbounds': [{'type': 'direct', 'inet4_bind_address': '198.18.0.3',
                               'inet6_bind_address': '2001:db8:1::3', 'bind_interface': 'wan0',
                               'routing_mark': MARK}],
            }, 'proxy')
            wait_port(10808, proxy)
            document = config([direct], core=core, dns='203.0.113.2', dns_type='udp', core_dns='203.0.113.2')  # the fake upstream speaks plain UDP
            document['log']['level'] = 'debug'
            document['dns']['disable_cache'] = True  # a cached answer would hide which server replied
            router = start(binary, document, 'router')
            for _ in range(80):
                if subprocess.run(['ip', 'link', 'show', 'orouter0'], capture_output=True).returncode == 0:
                    break
                if router.poll() is not None:
                    raise RuntimeError('TUN router exited')
                time.sleep(.05)
            time.sleep(.3)
            run('nft', '-f', '-', input=GUARD_NFT)  # the production guard; 10.25.0.0/24 is LAN here

            def request(executable, address, protocol):
                return subprocess.run([executable, '-c', CLIENT, address, protocol],
                                      capture_output=True, text=True, timeout=4,
                                      env=dict(os.environ, PYTHONHOME=sys.base_prefix))

            for address, suffix in [('203.0.113.2', '198.18.0.'), ('2001:db8:2::2', '2001:db8:1::')]:
                for protocol in ['tcp', 'udp']:
                    for executable, ending in [(direct, '1'), (sys.executable, '3')]:
                        result = request(executable, address, protocol)
                        assert result.returncode == 0 and result.stdout.strip() == suffix + ending, (address, protocol, ending, result.stderr, result.stdout)
            result = request(sys.executable, '203.0.113.2', 'dns')
            assert result.stdout.strip() == '203.0.113.53', (result.stderr, result.stdout)
            print('PASS: exact executable bypass, default SOCKS, TCP + UDP, IPv4 + IPv6, hijacked DNS', flush=True)
            proxy.terminate()
            proxy.wait(timeout=5)
            for address in ['203.0.113.2', '2001:db8:2::2']:
                for protocol in ['tcp', 'udp']:
                    assert request(direct, address, protocol).returncode == 0
                    assert request(sys.executable, address, protocol).returncode != 0
            assert request(sys.executable, '10.25.0.2', 'tcp').returncode == 0
            assert request(sys.executable, '203.0.113.2', 'dns').returncode != 0
            # The core resolves its server while the VPN is down; through the VPN it would deadlock.
            assert request(core, '203.0.113.2', 'dns').stdout.strip() == '203.0.113.53'
            print('PASS: proxy stopped → exceptions, LAN and core DNS work; other TCP/UDP/DNS fails', flush=True)
            router.terminate()
            router.wait(timeout=5)
            for address in ['203.0.113.2', '2001:db8:2::2']:
                assert request(direct, address, 'tcp').returncode != 0
            assert request(sys.executable, '10.25.0.2', 'tcp').returncode == 0
            run('nft', 'delete', 'table', 'inet', 'omarchy-router')
            assert request(sys.executable, '203.0.113.2', 'tcp').returncode == 0
            print('PASS: router stopped → guard blocks internet; emergency removal restores direct', flush=True)
        except BaseException:
            for args in [('ip', 'rule'), ('ip', 'route', 'show', 'table', 'all'),
                         ('ip', '-s', 'link', 'show', 'orouter0'), ('nft', 'list', 'ruleset')]:
                print(subprocess.run(args, text=True, capture_output=True).stdout, file=sys.stderr)
            logs.flush()
            logs.seek(0)
            print(logs.read()[-16000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(children):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            logs.close()


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if len(sys.argv) == 2:
        environment = dict(os.environ, PROTOTYPE_HOST_NETNS=os.readlink('/proc/self/ns/net'))
        raise SystemExit(subprocess.call(['unshare', '--user', '--map-root-user', '--net',
                                         sys.executable, str(HERE), binary, '--isolated'], env=environment))
    isolated(binary)
