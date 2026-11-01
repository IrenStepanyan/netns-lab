#!/usr/bin/env bash
pkill -f "build/device" 2>/dev/null; pkill -f "build/mitm" 2>/dev/null
pkill -f "build/recvfile" 2>/dev/null; pkill -f "tcpdump" 2>/dev/null
for n in pc1 d1 mitm d2 pc2; do ip netns del "$n" 2>/dev/null; done
echo "lab removed"
