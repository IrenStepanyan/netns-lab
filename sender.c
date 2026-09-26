/*
 * sender.c
 * Runs inside ns_sender. Connects to the receiver over TCP and sends
 * one message.
 *
 * Compile: gcc -o sender sender.c
 * Run:     sudo ip netns exec ns_sender ./sender
 */

#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit
#include <string.h>     // strlen
#include <unistd.h>     // close, write
#include <arpa/inet.h>  // sockaddr_in, htons, inet_pton
#include <sys/socket.h> // socket, connect

#define TARGET_HOST "10.0.0.2"   // receiver's IP
#define TARGET_PORT 5000
#define MESSAGE "Hello from sender namespace!"

int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;

    /* 1. Create the socket: IPv4 (AF_INET), TCP (SOCK_STREAM) */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /* 2. Fill in the address struct of the machine we want to reach */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    if (inet_pton(AF_INET, TARGET_HOST, &server_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    /* 3. connect: perform the TCP 3-way handshake (SYN, SYN-ACK, ACK) */
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }
    printf("[sender] Connected to %s:%d\n", TARGET_HOST, TARGET_PORT);

    /* 4. send: transmit the raw bytes of our message */
    ssize_t bytes_sent = send(sock_fd, MESSAGE, strlen(MESSAGE), 0);
    if (bytes_sent < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }
    printf("[sender] Sent: %s\n", MESSAGE);

    /* 5. Clean up */
    close(sock_fd);
    return 0;
}
