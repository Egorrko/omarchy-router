#!/bin/sh
# Offline snapshot for when the internet is gone: run it, bring the archive back to the agent later.
#   sudo ./diagnose.sh            # -> diag/<time>.tar.gz
# Read-only: changes no routes, rules or services; only sends a few test requests.
set -u
[ "$(id -u)" = 0 ] || { echo 'run with sudo'; exit 1; }
HERE=$(dirname "$(readlink -f "$0")")
USR=${SUDO_USER:-root}
UHOME=$(getent passwd "$USR" | cut -d: -f6)
MARK=21330  # sing-box's own mark: skips our TUN (ip rule) and passes the guard = bare network
NAME=$(date +%F_%H%M%S)
OUT="$HERE/diag/$NAME"
mkdir -p "$OUT"

# c FILE CMD...: run with a timeout, keep stdout+stderr and the exit code
c() { f=$1; shift; printf '  %s\n' "$*" >&2; { echo "\$ $*"; timeout -k 2 15 "$@" 2>&1; echo "[exit $?]"; echo; } >>"$OUT/$f"; }

state() {  # $1 = before|after: counters around the tests show what dropped or queued
    c "nft-$1.txt" nft list ruleset
    c "nfqueue-$1.txt" cat /proc/net/netfilter/nfnetlink_queue
    c "netstat-$1.txt" nstat -az
}

echo "writing $OUT"
c system.txt date -Is
c system.txt uname -a
c system.txt uptime

c net.txt ip -br link
c net.txt ip addr
c net.txt ip rule
c net.txt ip -6 rule
c net.txt ip route show table all
c net.txt ip -6 route show table all
c net.txt cat /etc/resolv.conf
c net.txt resolvectl status
c net.txt ss -lntup
c net.txt ss -s
c net.txt ss -tunp state established
c net.txt sh -c 'wc -l /proc/net/nf_conntrack; cat /proc/sys/net/netfilter/nf_conntrack_max'
c net.txt sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.enp5s0.rp_filter

c procs.txt sh -c "ps -eo pid,ppid,user,etime,args | grep -iE 'happ|xray|sing-box|throne|zapret|nfqws' | grep -v grep"
for p in $(pgrep -f 'nfqws|zapret-rust'); do c procs.txt sh -c "tr '\0' ' ' </proc/$p/cmdline; echo"; done

c services.txt systemctl --no-pager status omarchy-router omarchy-router-guard happd
c services.txt systemctl --no-pager --failed

# ours
c router.txt cat /run/omarchy-router/config.json
c router.txt cat /etc/omarchy-router/guard.nft
c router.txt cat "$UHOME/.config/omarchy-router/exceptions.json"
c router.txt git -C "$HERE" log --oneline -3
c router.txt git -C "$HERE" status --short

# zapret (runs by hand from this dir)
c zapret.txt cat "$HERE/conf.env"
c zapret.txt tail -n 300 "$HERE/logs/zapret.log"

# Happ: routing only, not subscriptions (they hold keys)
c happ.txt tail -n 300 /var/log/happd.log
c happ.txt cat "$UHOME/.config/Happ/routing.json"
for f in "$UHOME"/.local/share/Happ/logs/*; do c happ.txt tail -n 100 "$f"; done

state before

# Each test answers one question; compare them to find the broken hop.
GW=$(ip -4 route show default dev enp5s0 2>/dev/null | awk '{print $3; exit}')
{
echo "== 1. LAN: gateway $GW";           timeout 5 ping -n -c 3 -W 1 "${GW:-192.168.0.1}" | tail -2
echo "== 2. bare internet (bypass TUN+guard)"; timeout 5 ping -m $MARK -n -c 3 -W 1 1.1.1.1 | tail -2
echo "== 3. default path ping (TUN)";    timeout 5 ping -n -c 3 -W 1 1.1.1.1 | tail -2
echo "== 4. Happ SOCKS alive";           curl -sS -m 10 -o /dev/null -w '%{http_code} %{time_total}s\n' --socks5-hostname 127.0.0.1:10808 https://www.google.com/generate_204
echo "== 5. default path HTTPS (TUN -> Happ)"; curl -sS -m 10 -o /dev/null -w '%{http_code} %{time_total}s\n' https://www.google.com/generate_204
echo "== 6. DNS via router hijack";     dig +time=3 +tries=1 @1.1.1.1 google.com A +short
echo "== 7. DNS via system resolver";   dig +time=3 +tries=1 google.com A +short
echo "== 8. bare TLS per host (direct path, zapret applies here)"
timeout -k 2 30 python3 - "$MARK" <<'EOF'
import socket, ssl, subprocess, sys, time
mark = int(sys.argv[1])
for host in ['example.com', 'www.youtube.com', 'discord.com', 'rutracker.org', 'steamcommunity.com']:
    t = time.monotonic()
    try:
        # getaddrinfo can't be timed out and hangs for ages when DNS is dead
        out = subprocess.run(['timeout', '4', 'getent', 'ahostsv4', host], capture_output=True, text=True).stdout
        if not out: raise OSError('DNS: no answer in 4 s')
        ip = out.split()[0]
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, 36, mark); s.settimeout(6)  # 36 = SO_MARK
        s.connect((ip, 443))
        with ssl.create_default_context().wrap_socket(s, server_hostname=host) as tls:
            tls.sendall(f'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            res = tls.recv(64).split(b'\r\n')[0].decode(errors='replace')
    except Exception as e:
        res = f'FAIL {type(e).__name__}: {e}'
    print(f'  {host:<20} {round((time.monotonic() - t) * 1000):>5} ms  {res}')
EOF
} 2>&1 | tee "$OUT/tests.txt"

state after

# logs last: they include what the tests just triggered
c journal-ours.txt journalctl -b --no-pager --since -3h -u omarchy-router -u omarchy-router-guard -u happd
c journal-net.txt journalctl -b --no-pager --since -3h -u NetworkManager -u systemd-networkd -u systemd-resolved -u iwd
c journal-kernel.txt journalctl -b --no-pager --since -3h -k
c journal-all.txt journalctl -b --no-pager --since -30min
c journal-boots.txt journalctl --list-boots --no-pager

tar -C "$HERE/diag" -czf "$OUT.tar.gz" "$NAME" && rm -rf "$OUT"
chown -R "$USR": "$HERE/diag"
echo "done: $OUT.tar.gz"
