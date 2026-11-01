/*
 * dh.c - Diffie-Hellman handshake between Device1 (initiator) and Device2 (responder).
 *
 *   D1 -> D2 : nc(32) | A(256) | HMAC_psk("C" | nc | A)
 *   D2 -> D1 : ns(32) | B(256) | HMAC_psk("S" | nc | A | ns | B)
 *   both     : shared = g^(ab) mod p ; HKDF-SHA256(shared, salt = SHA256(transcript))
 *   D1 -> D2 : HMAC(confirm, "C" | transcript)        key confirmation
 *   D2 -> D1 : HMAC(confirm, "S" | transcript)
 * Every message is prefixed with a 2-byte big-endian length.
 */
#include "dh.h"
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* RFC 3526 group 14: 2048-bit MODP safe prime, generator 2 */
static const char *P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
#define PLEN 256
#define TRANSCRIPT_LEN (32 + PLEN + 32 + PLEN)

/* ---------- framing ---------- */
static int send_all(int fd, const uint8_t *b, size_t n)
{
    while (n) { ssize_t k = send(fd, b, n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
static int recv_all(int fd, uint8_t *b, size_t n)
{
    while (n) { ssize_t k = recv(fd, b, n, 0); if (k <= 0) return -1; b += k; n -= (size_t)k; }
    return 0;
}
static int send_msg(int fd, const uint8_t *b, size_t n)
{
    uint8_t h[2] = { (uint8_t)(n >> 8), (uint8_t)n };
    return send_all(fd, h, 2) || send_all(fd, b, n) ? -1 : 0;
}
static int recv_msg(int fd, uint8_t *b, size_t want)   /* exact length expected */
{
    uint8_t h[2];
    if (recv_all(fd, h, 2)) return -1;
    if ((size_t)(h[0] << 8 | h[1]) != want) return -1;
    return recv_all(fd, b, want);
}

/* ---------- crypto helpers ---------- */
static void hmac256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    unsigned int l = 32;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &l);
}

/* HKDF-SHA256 (RFC 5869), output up to 128 bytes */
static void hkdf(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen,
                 const char *info, uint8_t *okm, size_t olen)
{
    uint8_t prk[32], t[32 + 64 + 1], prev[32];
    size_t il = strlen(info), tl = 0, done = 0;
    hmac256(salt, slen, ikm, ilen, prk);
    for (uint8_t i = 1; done < olen; i++) {
        memcpy(t, prev, tl);                       /* T(i-1) (empty for i = 1) */
        memcpy(t + tl, info, il);
        t[tl + il] = i;
        hmac256(prk, 32, t, tl + il + 1, prev);
        tl = 32;
        size_t c = olen - done < 32 ? olen - done : 32;
        memcpy(okm + done, prev, c);
        done += c;
    }
}

typedef struct { BIGNUM *p, *g, *q, *x, *pub; BN_CTX *ctx; } dh_t;

static int dh_init(dh_t *d, uint8_t pub_out[PLEN])
{
    memset(d, 0, sizeof *d);
    d->ctx = BN_CTX_new();
    d->p = NULL; BN_hex2bn(&d->p, P_HEX);
    d->g = BN_new(); BN_set_word(d->g, 2);
    d->q = BN_dup(d->p); BN_sub_word(d->q, 1); BN_rshift1(d->q, d->q);      /* (p-1)/2 */
    d->x = BN_new(); d->pub = BN_new();
    if (!BN_rand(d->x, 512, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) return -1; /* private */
    BN_add_word(d->x, 2);
    BN_mod_exp(d->pub, d->g, d->x, d->p, d->ctx);                           /* g^x mod p */
    return BN_bn2binpad(d->pub, pub_out, PLEN) == PLEN ? 0 : -1;
}

/* peer value must be in [2, p-2] and in the prime-order subgroup (y^q == 1) */
static int dh_shared(dh_t *d, const uint8_t peer[PLEN], uint8_t shared[PLEN])
{
    int rc = -1;
    BIGNUM *y = BN_bin2bn(peer, PLEN, NULL), *pm2 = BN_dup(d->p), *chk = BN_new(), *s = BN_new();
    BN_sub_word(pm2, 2);
    if (BN_cmp(y, BN_value_one()) > 0 && BN_cmp(y, pm2) <= 0) {
        BN_mod_exp(chk, y, d->q, d->p, d->ctx);
        if (BN_is_one(chk)) {
            BN_mod_exp(s, y, d->x, d->p, d->ctx);
            rc = BN_bn2binpad(s, shared, PLEN) == PLEN ? 0 : -1;
        }
    }
    BN_free(y); BN_free(pm2); BN_free(chk); BN_free(s);
    return rc;
}

static void dh_free(dh_t *d)
{
    BN_clear_free(d->x); BN_free(d->p); BN_free(d->g); BN_free(d->q); BN_free(d->pub);
    BN_CTX_free(d->ctx);
}

static void derive(const uint8_t *shared, const uint8_t *transcript, int initiator,
                   session_keys *k, uint8_t confirm[32])
{
    uint8_t salt[32], okm[104];
    SHA256(transcript, TRANSCRIPT_LEN, salt);
    hkdf(salt, 32, shared, PLEN, "secure-inline-v1", okm, sizeof okm);
    const uint8_t *k_c2s = okm, *k_s2c = okm + 32, *s_c2s = okm + 64, *s_s2c = okm + 68;
    memcpy(k->tx_key, initiator ? k_c2s : k_s2c, 32);
    memcpy(k->rx_key, initiator ? k_s2c : k_c2s, 32);
    memcpy(k->tx_salt, initiator ? s_c2s : s_s2c, 4);
    memcpy(k->rx_salt, initiator ? s_s2c : s_c2s, 4);
    memcpy(confirm, okm + 72, 32);
    OPENSSL_cleanse(okm, sizeof okm);
}

/* mac = HMAC_psk(tag | parts...) built in a scratch buffer */
static void psk_mac(const char *psk, char tag, const uint8_t *a, size_t alen, uint8_t out[32])
{
    uint8_t buf[1 + TRANSCRIPT_LEN];
    buf[0] = (uint8_t)tag;
    memcpy(buf + 1, a, alen);
    hmac256((const uint8_t *)psk, strlen(psk), buf, 1 + alen, out);
}
static void fin_mac(const uint8_t confirm[32], char tag, const uint8_t *tr, uint8_t out[32])
{
    uint8_t buf[1 + TRANSCRIPT_LEN];
    buf[0] = (uint8_t)tag;
    memcpy(buf + 1, tr, TRANSCRIPT_LEN);
    hmac256(confirm, 32, buf, 1 + TRANSCRIPT_LEN, out);
}

int initiator_handshake(int fd, const char *psk, session_keys *out)
{
    dh_t d; uint8_t tr[TRANSCRIPT_LEN];                 /* nc | A | ns | B */
    uint8_t m1[32 + PLEN + 32], m2[32 + PLEN + 32], mac[32], shared[PLEN], confirm[32], f[32];
    int rc = -1;
    if (dh_init(&d, tr + 32) < 0) return -1;
    RAND_bytes(tr, 32);                                 /* nc */
    memcpy(m1, tr, 32 + PLEN);
    psk_mac(psk, 'C', tr, 32 + PLEN, m1 + 32 + PLEN);
    if (send_msg(fd, m1, sizeof m1) || recv_msg(fd, m2, sizeof m2)) goto out;

    memcpy(tr + 32 + PLEN, m2, 32 + PLEN);              /* ns | B */
    psk_mac(psk, 'S', tr, TRANSCRIPT_LEN, mac);
    if (CRYPTO_memcmp(mac, m2 + 32 + PLEN, 32)) { fprintf(stderr, "[hs] responder auth failed\n"); goto out; }
    if (dh_shared(&d, tr + 32 + PLEN + 32, shared)) { fprintf(stderr, "[hs] bad DH value\n"); goto out; }
    derive(shared, tr, 1, out, confirm);

    fin_mac(confirm, 'C', tr, f);
    if (send_msg(fd, f, 32) || recv_msg(fd, mac, 32)) goto out;
    fin_mac(confirm, 'S', tr, f);
    if (CRYPTO_memcmp(mac, f, 32)) { fprintf(stderr, "[hs] key confirmation failed\n"); goto out; }
    rc = 0;
out:
    dh_free(&d); OPENSSL_cleanse(shared, sizeof shared);
    return rc;
}

int responder_handshake(int fd, const char *psk, session_keys *out)
{
    dh_t d; uint8_t tr[TRANSCRIPT_LEN];
    uint8_t m1[32 + PLEN + 32], m2[32 + PLEN + 32], mac[32], shared[PLEN], confirm[32], f[32];
    int rc = -1;
    if (recv_msg(fd, m1, sizeof m1)) return -1;
    memcpy(tr, m1, 32 + PLEN);                          /* nc | A */
    psk_mac(psk, 'C', tr, 32 + PLEN, mac);
    if (CRYPTO_memcmp(mac, m1 + 32 + PLEN, 32)) { fprintf(stderr, "[hs] initiator auth failed\n"); return -1; }
    if (dh_init(&d, tr + 32 + PLEN + 32)) return -1;    /* B */
    RAND_bytes(tr + 32 + PLEN, 32);                     /* ns */
    memcpy(m2, tr + 32 + PLEN, 32 + PLEN);
    psk_mac(psk, 'S', tr, TRANSCRIPT_LEN, m2 + 32 + PLEN);
    if (send_msg(fd, m2, sizeof m2)) goto out;

    if (dh_shared(&d, tr + 32, shared)) { fprintf(stderr, "[hs] bad DH value\n"); goto out; }
    derive(shared, tr, 0, out, confirm);

    if (recv_msg(fd, mac, 32)) goto out;
    fin_mac(confirm, 'C', tr, f);
    if (CRYPTO_memcmp(mac, f, 32)) { fprintf(stderr, "[hs] key confirmation failed\n"); goto out; }
    fin_mac(confirm, 'S', tr, f);
    if (send_msg(fd, f, 32)) goto out;
    rc = 0;
out:
    dh_free(&d); OPENSSL_cleanse(shared, sizeof shared);
    return rc;
}
