/* sendfile FILE HOST [PORT]  - PC1: plain TCP client; the devices protect it transparently */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s FILE HOST [PORT]\n", argv[0]); return 2; }
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(argc > 3 ? atoi(argv[3]) : 5001) };
    if (inet_pton(AF_INET, argv[2], &a.sin_addr) != 1) { fprintf(stderr, "bad host\n"); return 2; }
    FILE *f = fopen(argv[1], "rb"); if (!f) { perror("fopen"); return 1; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { perror("connect"); return 1; }
    char b[65536]; size_t n, tot = 0;
    while ((n = fread(b, 1, sizeof b, f)) > 0) {
        for (size_t o = 0; o < n;) { ssize_t k = send(s, b + o, n - o, 0); if (k <= 0) { perror("send"); return 1; } o += (size_t)k; }
        tot += n;
    }
    close(s); printf("sent %zu bytes\n", tot); return 0;
}
