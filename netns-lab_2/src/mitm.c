/* mitm.c - man-in-the-middle box: forwards frames between two interfaces, optionally attacks.
 *   --mode pass    forward untouched
 *   --mode flip    flip one bit in 1 of every 20 protected data frames  -> GCM tag must fail
 *   --mode replay  send every protected data frame twice                -> anti-replay must drop */
#include <getopt.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "pkt.h"

int main(int argc, char **argv)
{
    const char *ia = "eth0", *ib = "eth1", *mode = "pass";
    int port = 5001, ch;
    static struct option lo[] = { {"if-a",1,0,'a'}, {"if-b",1,0,'b'}, {"port",1,0,'p'}, {"mode",1,0,'m'}, {0,0,0,0} };
    while ((ch = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        if (ch == 'a') ia = optarg; else if (ch == 'b') ib = optarg;
        else if (ch == 'p') port = atoi(optarg); else if (ch == 'm') mode = optarg;
        else return 2;
    }
    int fd[2] = { open_raw(ia), open_raw(ib) };
    if (fd[0] < 0 || fd[1] < 0) return 1;
    struct pollfd pf[2] = { { fd[0], POLLIN, 0 }, { fd[1], POLLIN, 0 } };
    static uint8_t buf[FRAME_MAX];
    unsigned long n = 0;
    for (;;) {
        poll(pf, 2, -1);
        for (int i = 0; i < 2; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            struct sockaddr_ll from; socklen_t fl = sizeof from;
            ssize_t len = recvfrom(fd[i], buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
            if (len <= 0 || from.sll_pkttype == PACKET_OUTGOING) continue;
            int out = fd[1 - i];
            tcp_pkt p;
            if (strcmp(mode, "pass") && parse_tcp(buf, (size_t)len, &p) && p.plen &&
                (p.sport == port || p.dport == port)) {
                n++;
                if (!strcmp(mode, "flip")) {
                    if (n % 20 == 0) { buf[len - 1 - 8 - 3] ^= 1; printf("[mitm] tampered frame #%lu\n", n); fflush(stdout); }
                } else {
                    send(out, buf, (size_t)len, 0);
                    printf("[mitm] replayed frame #%lu\n", n); fflush(stdout);
                }
            }
            send(out, buf, (size_t)len, 0);
        }
    }
}
