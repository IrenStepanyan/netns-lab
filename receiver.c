/*
 * receiver.c
 * Runs inside ns_receiver. Listens for a TCP connection and prints
 * whatever data it receives.
 *
 * Compile: gcc -o receiver receiver.c
 * Run:     sudo ip netns exec ns_receiver ./receiver
 */

#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit
#include <string.h>     // memset
#include <unistd.h>     // close, read
#include <arpa/inet.h>  // sockaddr_in, htons, inet_pton
#include <sys/socket.h> // socket, bind, listen, accept

#define HOST "10.0.0.2"   // receiver's own IP inside ns_receiver
#define PORT 5000
#define BUF_SIZE 1024

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUF_SIZE];

    /* 1. Create the socket: IPv4 (AF_INET), TCP (SOCK_STREAM) */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /* Allow quick restart of the program without "Address already in use" */
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    /* 2. Fill in the address struct we want to bind to */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;                 // IPv4
    server_addr.sin_port = htons(PORT);               // host-to-network byte order
    if (inet_pton(AF_INET, HOST, &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    /* 3. bind: claim this address/port as ours */
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    /* 4. listen: enter passive mode, queue up to 1 pending connection */
    if (listen(server_fd, 1) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[receiver] Listening on %s:%d ...\n", HOST, PORT);

    /* 5. accept: block until a client connects, get a new socket for them */
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }
    printf("[receiver] Connection established from %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    /* 6. recv: read the bytes the sender transmits */
    memset(buffer, 0, BUF_SIZE);
    ssize_t bytes_received = recv(client_fd, buffer, BUF_SIZE - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
        exit(EXIT_FAILURE);
    }
    printf("[receiver] Received: %s\n", buffer);

    /* 7. Clean up */
    close(client_fd);
    close(server_fd);
    return 0;
}
