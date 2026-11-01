# netns-lab

```
 PC1 --eth0 [ D1 ] eth1 ==== [ MITM ] ==== eth0 [ D2 ] eth1-- PC2
10.0.0.1     encrypt   192.168.100.1   sniff/tamper/replay   192.168.100.2   decrypt   10.0.0.2
```

## Files
| File | Role |
|---|---|
| `src/pkt.c/.h` | Ethernet/IPv4/TCP parsing, frame rebuild, IP+TCP checksum recalculation, AF_PACKET socket helper |
| `src/dh.c/.h` | Diffie-Hellman (RFC 3526 group 14, OpenSSL BIGNUM), PSK-authenticated handshake, HKDF-SHA256 |
| `src/device.c` | D1/D2: AES-256-GCM encrypt/decrypt of the TCP payload, anti-replay window, forwarding loop |
| `src/mitm.c` | attacker box: `pass`, `flip` (corrupt 1 in 20 frames), `replay` (duplicate every frame) |
| `src/sendfile.c`, `src/recvfile.c` | plain TCP file sender (PC1) / receiver (PC2) |
| `scripts/*.sh` | lab build (netns + veth), teardown, automatic demo |

## Build and run
```bash
sudo apt install -y build-essential libssl-dev iproute2 ethtool tcpdump
make                                  # -> build/device build/mitm build/sendfile build/recvfile
sudo scripts/setup_lab.sh             # 5 namespaces, 4 veth pairs, MTU 1600 on D1<->D2, offloads off
sudo scripts/demo.sh pass             # 3 MB file, sha256 compared
sudo scripts/demo.sh flip             # "[drop] bad authentication tag"
sudo scripts/demo.sh replay           # "[drop] replay/too old"
sudo scripts/teardown_lab.sh
```
Manual (one terminal each; start D2 before D1; PSK must match):
```bash
sudo ip netns exec mitm build/mitm --mode pass
sudo ip netns exec mitm tcpdump -n -i eth1 -X "tcp port 5001"
sudo ip netns exec d2 build/device --role d2 --lan-if eth1 --wan-if eth0 --listen-ip 192.168.100.2 --port 5001 --psk lab-secret -v
sudo ip netns exec d1 build/device --role d1 --lan-if eth0 --wan-if eth1 --peer-ip 192.168.100.2 --port 5001 --psk lab-secret -v
sudo ip netns exec pc2 build/recvfile out.bin 5001
sudo ip netns exec pc1 build/sendfile in.bin 10.0.0.2 5001
sha256sum in.bin out.bin
```

## Protocol summary
* Handshake over a normal TCP connection D1->D2 (port 9000): nonces + DH public values authenticated with HMAC-SHA256(PSK), keys = HKDF-SHA256(shared, salt = SHA256(transcript)), then key confirmation.
* Data path: only TCP segments with payload on `--port`. Wire payload = `ciphertext | tag(16) | counter(8)`; nonce = 4-byte salt || counter; separate key and salt per direction; counter strictly increasing so no (key, nonce) reuse, retransmissions included.
* AAD = src IP, dst IP, sport, dport, seq, ack. Receiver drops anything that fails the tag or the 1024-entry replay window (fail closed).
* IP total length +24, IP header checksum and TCP checksum recomputed on both devices.

## Limits
IPv4 only, no fragments/VLAN, no rekeying (session ends at 2^40 packets), PSK instead of certificates, one handshake per process start.
