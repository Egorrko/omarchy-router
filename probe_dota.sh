#!/bin/sh
# Probe: where do Dota's extra ms come from? Run while a match is on (or the region list is open):
#   sudo ./probe_dota.sh
# Read-only. Raw ICMP to the relays Dota is talking to right now: mark 0x5352 skips our TUN
# (ip rule 9000) and passes the guard, so this is the bare network path. Compare with the
# in-game ping: equal -> the network; lower -> something on this host (TUN or zapret) adds it.
set -u
[ "$(id -u)" = 0 ] || { echo 'run with sudo'; exit 1; }

echo '== UDP flows to Valve relay ports seen by conntrack (dst, both directions seen = ASSURED)'
relays=$(awk '/udp/ && /dport=27[0-9][0-9][0-9] / && /ASSURED/ { for (i=1;i<=NF;i++) if ($i ~ /^dst=/) { print substr($i,5); break } }' \
    /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head -6)
echo "${relays:-none: no match running?}"

echo '== raw RTT (bypassing TUN and guard), ms'
for ip in $(echo "$relays" | awk '{print $2}') 109.172.92.159; do
    printf '%-16s ' "$ip"; ping -m 21330 -n -c 5 -i 0.3 -W 1 "$ip" | tail -1 | sed 's/.*= //'
done
echo '(109.172.92.159 is the Throne server: a VPN hop costs at least that)'

echo '== zapret: nft rules that queue packets, and queue counters'
nft list ruleset | grep -n -iE 'queue|zapret' || echo 'no queue rules'
echo 'queue portid total copymode range dropped user_dropped seq'
cat /proc/net/netfilter/nfnetlink_queue
