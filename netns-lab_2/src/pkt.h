#ifndef PKT_H
#define PKT_H
#include <stddef.h>
#include <stdint.h>

#define ETH_LEN 14
#define FRAME_MAX 65700

typedef struct {
    uint8_t *frame;      /* whole Ethernet frame                           */
    size_t   len;        /* frame length                                   */
    int      ihl, thl;   /* IPv4 / TCP header lengths in bytes             */
    uint8_t *ip, *tcp;   /* start of IP and TCP headers                    */
    uint8_t *payload;    /* start of TCP payload                           */
    size_t   plen;       /* payload length (Ethernet padding excluded)     */
    uint16_t sport, dport;
    uint32_t seq, ack;
} tcp_pkt;

/* 1 if frame is an unfragmented IPv4/TCP frame (p filled in), else 0 */
int    parse_tcp(uint8_t *frame, size_t len, tcp_pkt *p);
/* copy headers of p, attach new payload, fix IP total length, IP + TCP checksums */
size_t build_frame(const tcp_pkt *p, const uint8_t *payload, size_t plen, uint8_t *out);
/* AAD = src IP | dst IP | sport | dport | seq | ack  (20 raw header bytes) */
void   make_aad(const tcp_pkt *p, uint8_t aad[20]);
/* AF_PACKET socket bound to ifname, promiscuous */
int    open_raw(const char *ifname);

void     put_be64(uint8_t *b, uint64_t v);
uint64_t get_be64(const uint8_t *b);
#endif
