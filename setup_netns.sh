#!/bin/bash
# setup_netns.sh
# Creates two network namespaces (sender, receiver) connected by a veth pair.
# Run with: sudo ./setup_netns.sh

set -e  # exit immediately if any command fails

SENDER_NS="ns_sender"
RECEIVER_NS="ns_receiver"
VETH_SND="veth-snd"
VETH_RCV="veth-rcv"
SENDER_IP="10.0.0.1/24"
RECEIVER_IP="10.0.0.2/24"

echo "[*] Creating namespaces..."
ip netns add "$SENDER_NS"
ip netns add "$RECEIVER_NS"

echo "[*] Creating veth pair..."
ip link add "$VETH_SND" type veth peer name "$VETH_RCV"

echo "[*] Moving veth ends into namespaces..."
ip link set "$VETH_SND" netns "$SENDER_NS"
ip link set "$VETH_RCV" netns "$RECEIVER_NS"

echo "[*] Assigning IP addresses..."
ip netns exec "$SENDER_NS"   ip addr add "$SENDER_IP" dev "$VETH_SND"
ip netns exec "$RECEIVER_NS" ip addr add "$RECEIVER_IP" dev "$VETH_RCV"

echo "[*] Bringing interfaces up..."
ip netns exec "$SENDER_NS"   ip link set "$VETH_SND" up
ip netns exec "$RECEIVER_NS" ip link set "$VETH_RCV" up
ip netns exec "$SENDER_NS"   ip link set lo up
ip netns exec "$RECEIVER_NS" ip link set lo up

echo "[*] Testing connectivity..."
ip netns exec "$SENDER_NS" ping -c 2 10.0.0.2

echo "[+] Done. Namespaces ready: $SENDER_NS (10.0.0.1), $RECEIVER_NS (10.0.0.2)"
