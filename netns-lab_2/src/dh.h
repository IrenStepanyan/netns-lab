#ifndef DH_H
#define DH_H
#include <stdint.h>

typedef struct {
    uint8_t tx_key[32], rx_key[32];   /* AES-256 keys: what we encrypt / decrypt with */
    uint8_t tx_salt[4], rx_salt[4];   /* fixed 4 bytes of the 96-bit GCM nonce        */
} session_keys;

/* Both return 0 on success, -1 on any failure (bad MAC, bad DH value, I/O error).
 * fd is a connected ordinary TCP socket between the two devices. */
int initiator_handshake(int fd, const char *psk, session_keys *out);
int responder_handshake(int fd, const char *psk, session_keys *out);
#endif
