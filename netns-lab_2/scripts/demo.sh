#!/usr/bin/env bash
# End-to-end demo. Usage: sudo scripts/demo.sh [pass|flip|replay]
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-pass}; PSK=${PSK:-lab-secret}; LOG=/tmp/lab; mkdir -p $LOG
[ -x build/device ] || make
head -c 3000000 /dev/urandom > $LOG/in.bin            # 3 MB test file

ip netns exec mitm build/mitm --mode "$MODE" >$LOG/mitm.log 2>&1 &
ip netns exec mitm tcpdump -n -i eth1 -w $LOG/mitm.pcap "tcp port 5001" >/dev/null 2>&1 &
ip netns exec d2 build/device --role d2 --lan-if eth1 --wan-if eth0 \
      --listen-ip 192.168.100.2 --port 5001 --psk "$PSK" -v >$LOG/d2.log 2>&1 &
sleep 1
ip netns exec d1 build/device --role d1 --lan-if eth0 --wan-if eth1 \
      --peer-ip 192.168.100.2 --port 5001 --psk "$PSK" -v >$LOG/d1.log 2>&1 &
sleep 3

ip netns exec pc2 build/recvfile $LOG/out.bin 5001 &
sleep 1
ip netns exec pc1 timeout 60 build/sendfile $LOG/in.bin 10.0.0.2 5001 || true
sleep 1
sha256sum $LOG/in.bin $LOG/out.bin 2>/dev/null || true
echo "--- logs in $LOG (d1.log d2.log mitm.log mitm.pcap)"
