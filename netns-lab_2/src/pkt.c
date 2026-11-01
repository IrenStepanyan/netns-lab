#include "pkt.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void put_be64(uint8_t *b, uint64_t v) { for (int i = 7; i >= 0; i--) { b[i] = v & 0xff; v >>= 8; } }
uint64_t get_be64(const uint8_t *b)   { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | b[i]; return v; }
static uint32_t get_be32(const uint8_t *b) { return (uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]; }

/* RFC 1071: accumulate 16-bit big-endian words */
static uint32_t sum16(const uint8_t *d, size_t n, uint32_t acc)
{
    for (; n > 1; d += 2, n -= 2) acc += (uint32_t)(d[0] << 8 | d[1]);
    if (n) acc += (uint32_t)(d[0] << 8);
    return acc;
}
static uint16_t fold(uint32_t acc)
{
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc;
}

int parse_tcp(uint8_t *f, size_t len, tcp_pkt *p)
{
    if (len < ETH_LEN + 20 || f[12] != 0x08 || f[13] != 0x00) return 0;
    uint8_t *ip = f + ETH_LEN;
    size_t avail = len - ETH_LEN;
    int ihl = (ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 6) return 0;
    size_t total = (size_t)(ip[2] << 8 | ip[3]);
    if (total > avail || total < (size_t)ihl + 20) return 0;
    if ((ip[6] << 8 | ip[7]) & 0x3fff) return 0;          /* fragment: not handled */
    uint8_t *tcp = ip + ihl;
    size_t tlen = total - ihl;
    int thl = (tcp[12] >> 4) * 4;
    if (thl < 20 || (size_t)thl > tlen) return 0;

    p->frame = f; p->len = len; p->ihl = ihl; p->thl = thl; p->ip = ip; p->tcp = tcp;
    p->payload = tcp + thl; p->plen = tlen - thl;
    p->sport = (uint16_t)(tcp[0] << 8 | tcp[1]);
    p->dport = (uint16_t)(tcp[2] << 8 | tcp[3]);
    p->seq = get_be32(tcp + 4);
    p->ack = get_be32(tcp + 8);
    return 1;
}

void make_aad(const tcp_pkt *p, uint8_t aad[20])
{
    memcpy(aad, p->ip + 12, 8);        /* src IP, dst IP */
    memcpy(aad + 8, p->tcp, 12);       /* sport, dport, seq, ack */
}

size_t build_frame(const tcp_pkt *p, const uint8_t *payload, size_t plen, uint8_t *out)
{
    size_t hdr = ETH_LEN + p->ihl + p->thl;
    memcpy(out, p->frame, hdr);
    memcpy(out + hdr, payload, plen);

    uint8_t *ip = out + ETH_LEN, *tcp = ip + p->ihl;
    size_t total = (size_t)p->ihl + p->thl + plen;
    ip[2] = total >> 8; ip[3] = total & 0xff;                    /* new IP total length */
    ip[10] = ip[11] = 0;
    uint16_t c = fold(sum16(ip, p->ihl, 0));
    ip[10] = c >> 8; ip[11] = c & 0xff;                          /* IP header checksum */

    size_t seglen = (size_t)p->thl + plen;
    tcp[16] = tcp[17] = 0;
    uint32_t acc = sum16(ip + 12, 8, 0) + 6 + (uint32_t)seglen;  /* pseudo header */
    acc = sum16(tcp, seglen, acc);
    c = fold(acc);
    tcp[16] = c >> 8; tcp[17] = c & 0xff;                        /* TCP checksum */
    return hdr + plen;
}

int open_raw(const char *ifname)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) { perror("socket(AF_PACKET)"); return -1; }
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(ifname);
    if (!sll.sll_ifindex) { fprintf(stderr, "no such interface: %s\n", ifname); close(s); return -1; }
    if (bind(s, (struct sockaddr *)&sll, sizeof sll) < 0) { perror("bind"); close(s); return -1; }
    struct packet_mreq mr = {0};
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;                  /* see frames for other hosts' MACs */
    if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) < 0) perror("promisc");
    return s;
}
