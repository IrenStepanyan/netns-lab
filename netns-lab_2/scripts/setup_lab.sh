#!/usr/bin/env bash
# Build: pc1 -- d1 == mitm == d2 -- pc2
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

NS="pc1 d1 mitm d2 pc2"
for n in $NS; do ip netns add "$n"; ip -n "$n" link set lo up; done

ip link add eth0 netns pc1  type veth peer name eth0 netns d1
ip link add eth1 netns d1   type veth peer name eth0 netns mitm
ip link add eth1 netns mitm type veth peer name eth0 netns d2
ip link add eth1 netns d2   type veth peer name eth0 netns pc2

ip -n pc1 addr add 10.0.0.1/24 dev eth0
ip -n pc2 addr add 10.0.0.2/24 dev eth0
# management IPs used ONLY for the DH handshake between the devices
ip -n d1 addr add 192.168.100.1/24 dev eth1
ip -n d2 addr add 192.168.100.2/24 dev eth0

# the ciphertext packets are 24 bytes larger than the originals -> bigger MTU on the
# D1<->D2 segment (the PC-facing links stay at 1500)
for spec in d1:eth1 mitm:eth0 mitm:eth1 d2:eth0; do ip -n "${spec%%:*}" link set "${spec##*:}" mtu 1600; done

# raw sockets must see real, final checksums/segments: turn offloads off on every veth end
for spec in pc1:eth0 d1:eth0 d1:eth1 mitm:eth0 mitm:eth1 d2:eth0 d2:eth1 pc2:eth0; do
  ip netns exec "${spec%%:*}" ethtool -K "${spec##*:}" tx off rx off tso off gso off gro off >/dev/null
  ip -n "${spec%%:*}" link set "${spec##*:}" up
done
# less background noise on the wire (IPv6 ND/MLD)
for n in $NS; do ip netns exec "$n" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true; done
echo "lab ready"; ip netns list
