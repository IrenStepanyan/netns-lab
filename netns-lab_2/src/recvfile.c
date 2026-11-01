/* recvfile OUT [PORT]  - PC2: plain TCP server that writes the received stream to OUT */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s OUT [PORT]\n", argv[0]); return 2; }
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(argc > 2 ? atoi(argv[2]) : 5001) };
    int srv = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) || listen(srv, 1)) { perror("bind/listen"); return 1; }
    int c = accept(srv, NULL, NULL);
    FILE *f = fopen(argv[1], "wb"); if (!f) { perror("fopen"); return 1; }
    char b[65536]; ssize_t n; size_t tot = 0;
    while ((n = recv(c, b, sizeof b, 0)) > 0) { fwrite(b, 1, (size_t)n, f); tot += (size_t)n; }
    fclose(f); printf("received %zu bytes -> %s\n", tot, argv[1]); return 0;
}
