/*
 * device.c - inline secure device (Device1 / Device2)
 *
 *   PC1 --[lan]-- D1 --[wan]== MITM ==[wan]-- D2 --[lan]-- PC2
 *
 * Transparent L2 bump-in-the-wire built on two AF_PACKET sockets.
 *  - frames from LAN: selected TCP segments with payload -> AES-256-GCM(payload) -> WAN
 *  - frames from WAN: selected TCP segments with payload -> verify, anti-replay, decrypt -> LAN
 *  - everything else is forwarded unchanged.
 *
 * Protected payload on the wire:  ciphertext(n) | GCM tag(16) | counter(8, big-endian)
 * Nonce (96 bit) = 4-byte per-direction salt (HKDF) || 64-bit counter (never reused).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dh.h"
#include "pkt.h"

#define TAG_LEN 16
#define CTR_LEN 8
#define OVERHEAD (TAG_LEN + CTR_LEN)
#define MAX_PORTS 16
#define WIN 1024
#define MAX_PACKETS_PER_KEY (1ULL << 40)

/* ---------- anti-replay: sliding window of WIN counters ---------- */
typedef struct { int64_t hi; uint64_t seen[WIN]; } replay_t;   /* seen[c % WIN] = c + 1 */

static int replay_ok(const replay_t *w, uint64_t c)
{
    if ((int64_t)c > w->hi) return 1;
    uint64_t d = (uint64_t)(w->hi - (int64_t)c);
    return d < WIN && w->seen[c % WIN] != c + 1;
}
static void replay_commit(replay_t *w, uint64_t c)             /* only after the tag verified */
{
    w->seen[c % WIN] = c + 1;
    if ((int64_t)c > w->hi) w->hi = (int64_t)c;
}

/* ---------- channel ---------- */
typedef struct {
    session_keys k;
    uint64_t tx_ctr;
    replay_t win;
    unsigned long enc, dec, bad_tag, replay, fwd;
} channel_t;

static uint8_t scratch[FRAME_MAX];

static int protect(channel_t *c, const tcp_pkt *p, uint8_t *out, size_t *outlen)
{
    if (c->tx_ctr >= MAX_PACKETS_PER_KEY) { fprintf(stderr, "packet budget exhausted, re-handshake\n"); exit(1); }
    uint64_t ctr = c->tx_ctr++;                                 /* unique per packet */
    uint8_t nonce[12], aad[20];
    memcpy(nonce, c->k.tx_salt, 4);
    put_be64(nonce + 4, ctr);
    make_aad(p, aad);

    int l = 0, l2 = 0, ok = 0;
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(e, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(e, NULL, NULL, c->k.tx_key, nonce) == 1 &&
        EVP_EncryptUpdate(e, NULL, &l, aad, sizeof aad) == 1 &&
        EVP_EncryptUpdate(e, scratch, &l, p->payload, (int)p->plen) == 1 &&
        EVP_EncryptFinal_ex(e, scratch + l, &l2) == 1 &&
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_GET_TAG, TAG_LEN, scratch + p->plen) == 1)
        ok = 1;
    EVP_CIPHER_CTX_free(e);
    if (!ok) return -1;
    put_be64(scratch + p->plen + TAG_LEN, ctr);
    *outlen = build_frame(p, scratch, p->plen + OVERHEAD, out);
    c->enc++;
    return 0;
}

static int unprotect(channel_t *c, const tcp_pkt *p, uint8_t *out, size_t *outlen)
{
    if (p->plen < OVERHEAD) return -1;
    size_t clen = p->plen - OVERHEAD;
    uint64_t ctr = get_be64(p->payload + clen + TAG_LEN);
    if (!replay_ok(&c->win, ctr)) {
        c->replay++; printf("[drop] replay/too old counter=%llu\n", (unsigned long long)ctr); fflush(stdout);
        return -1;
    }
    uint8_t nonce[12], aad[20], tag[TAG_LEN];
    memcpy(nonce, c->k.rx_salt, 4);
    put_be64(nonce + 4, ctr);
    make_aad(p, aad);
    memcpy(tag, p->payload + clen, TAG_LEN);

    int l = 0, l2 = 0, ok = 0;
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(e, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(e, NULL, NULL, c->k.rx_key, nonce) == 1 &&
        EVP_DecryptUpdate(e, NULL, &l, aad, sizeof aad) == 1 &&
        EVP_DecryptUpdate(e, scratch, &l, p->payload, (int)clen) == 1 &&
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) == 1 &&
        EVP_DecryptFinal_ex(e, scratch + l, &l2) == 1)        /* <= 0 when the tag is wrong */
        ok = 1;
    EVP_CIPHER_CTX_free(e);
    if (!ok) {
        c->bad_tag++; printf("[drop] bad authentication tag counter=%llu\n", (unsigned long long)ctr); fflush(stdout);
        return -1;
    }
    replay_commit(&c->win, ctr);
    *outlen = build_frame(p, scratch, clen, out);
    c->dec++;
    return 0;
}

/* ---------- options / handshake ---------- */
typedef struct {
    int d1;
    const char *lan_if, *wan_if, *peer_ip, *listen_ip, *psk;
    int hs_port, nports, verbose;
    uint16_t ports[MAX_PORTS];
} opts_t;

static int handshake(const opts_t *o, session_keys *k)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)o->hs_port) };
    if (o->d1) {
        inet_pton(AF_INET, o->peer_ip, &a.sin_addr);
        for (int i = 0; i < 60; i++) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
                int rc = initiator_handshake(s, o->psk, k);
                close(s);
                return rc;
            }
            printf("[hs] waiting for D2 (%s)\n", strerror(errno)); fflush(stdout);
            close(s); sleep(1);
        }
        return -1;
    }
    inet_pton(AF_INET, o->listen_ip, &a.sin_addr);
    int srv = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) || listen(srv, 1)) { perror("bind/listen"); return -1; }
    printf("[hs] D2 listening on %s:%d\n", o->listen_ip, o->hs_port); fflush(stdout);
    int c = accept(srv, NULL, NULL);
    int rc = c < 0 ? -1 : responder_handshake(c, o->psk, k);
    if (c >= 0) close(c);
    close(srv);
    return rc;
}

static int selected(const opts_t *o, const tcp_pkt *p)
{
    if (!p->plen) return 0;                         /* SYN / pure ACK / FIN: untouched */
    for (int i = 0; i < o->nports; i++)
        if (p->sport == o->ports[i] || p->dport == o->ports[i]) return 1;
    return 0;
}

static void usage(const char *a)
{
    fprintf(stderr, "usage: %s --role d1|d2 --lan-if IF --wan-if IF --port N [--port N...] --psk KEY\n"
                    "          d1: --peer-ip IP     d2: --listen-ip IP     [--hs-port 9000] [-v]\n", a);
    exit(2);
}

int main(int argc, char **argv)
{
    opts_t o = { .hs_port = 9000 };
    int role_set = 0;
    static struct option lo[] = {
        {"role", 1, 0, 'r'}, {"lan-if", 1, 0, 'l'}, {"wan-if", 1, 0, 'w'}, {"peer-ip", 1, 0, 'p'},
        {"listen-ip", 1, 0, 'L'}, {"hs-port", 1, 0, 'H'}, {"port", 1, 0, 'P'}, {"psk", 1, 0, 'k'},
        {"verbose", 0, 0, 'v'}, {0, 0, 0, 0} };
    int ch;
    while ((ch = getopt_long(argc, argv, "v", lo, NULL)) != -1) {
        switch (ch) {
        case 'r': o.d1 = !strcmp(optarg, "d1"); role_set = o.d1 || !strcmp(optarg, "d2"); break;
        case 'l': o.lan_if = optarg; break;
        case 'w': o.wan_if = optarg; break;
        case 'p': o.peer_ip = optarg; break;
        case 'L': o.listen_ip = optarg; break;
        case 'H': o.hs_port = atoi(optarg); break;
        case 'P': if (o.nports < MAX_PORTS) o.ports[o.nports++] = (uint16_t)atoi(optarg); break;
        case 'k': o.psk = optarg; break;
        case 'v': o.verbose = 1; break;
        default: usage(argv[0]);
        }
    }
    if (!role_set || !o.lan_if || !o.wan_if || !o.psk || !o.nports ||
        (o.d1 && !o.peer_ip) || (!o.d1 && !o.listen_ip)) usage(argv[0]);

    static channel_t chn;
    chn.win.hi = -1;
    if (handshake(&o, &chn.k) < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    printf("[hs] session established, protecting %d port(s)\n", o.nports); fflush(stdout);

    int fd[2] = { open_raw(o.lan_if), open_raw(o.wan_if) };       /* 0 = LAN, 1 = WAN */
    if (fd[0] < 0 || fd[1] < 0) return 1;
    struct pollfd pf[2] = { { fd[0], POLLIN, 0 }, { fd[1], POLLIN, 0 } };
    static uint8_t in[FRAME_MAX], out[FRAME_MAX];
    time_t last = time(NULL);

    for (;;) {
        if (poll(pf, 2, 2000) < 0 && errno != EINTR) { perror("poll"); return 1; }
        for (int i = 0; i < 2; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            struct sockaddr_ll from; socklen_t fl = sizeof from;
            ssize_t n = recvfrom(fd[i], in, sizeof in, 0, (struct sockaddr *)&from, &fl);
            if (n <= 0) continue;
            if (from.sll_pkttype == PACKET_OUTGOING || from.sll_pkttype == PACKET_HOST) continue;

            const uint8_t *send_buf = in; size_t send_len = (size_t)n;
            tcp_pkt p;
            if (parse_tcp(in, (size_t)n, &p) && selected(&o, &p)) {
                if (i == 0) {                                      /* LAN -> WAN : encrypt */
                    if (protect(&chn, &p, out, &send_len)) continue;
                    if (o.verbose) printf("[enc] :%u->:%u seq=%u %zuB -> %zuB\n",
                                          p.sport, p.dport, p.seq, p.plen, p.plen + OVERHEAD);
                } else {                                           /* WAN -> LAN : verify + decrypt */
                    if (unprotect(&chn, &p, out, &send_len)) continue;
                    if (o.verbose) printf("[dec] :%u->:%u seq=%u ok\n", p.sport, p.dport, p.seq);
                }
                send_buf = out;
            } else chn.fwd++;
            if (send(fd[1 - i], send_buf, send_len, 0) < 0 && o.verbose) perror("send");
        }
        if (o.verbose && time(NULL) - last >= 5) {
            printf("[stats] enc=%lu dec=%lu bad_tag=%lu replay=%lu fwd=%lu\n",
                   chn.enc, chn.dec, chn.bad_tag, chn.replay, chn.fwd);
            fflush(stdout); last = time(NULL);
        }
        if (o.verbose) fflush(stdout);
    }
}
