#!/bin/bash
# cleanup_netns.sh
# Removes the namespaces created by setup_netns.sh.
# Run with: sudo ./cleanup_netns.sh

ip netns del ns_sender 2>/dev/null && echo "[*] Deleted ns_sender"
ip netns del ns_receiver 2>/dev/null && echo "[*] Deleted ns_receiver"
echo "[+] Cleanup complete."
