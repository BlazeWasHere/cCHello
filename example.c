//          Copyright Blaze 2021.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <err.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "cCHello.h"

#define RECV_MAX 1024
#define BACKLOG 256
#define PORT 1337

static int setup_socket(int port) {
    struct sockaddr_in address;
    int ret;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        err(EXIT_FAILURE, "Failed to create a socket");

    int optval = 1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (ret == -1)
        err(EXIT_FAILURE, "Failed to set socket opt");

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
    if (ret == -1)
        err(EXIT_FAILURE, "Failed to bind the socket");

    ret = listen(sock, BACKLOG);
    if (ret == -1)
        err(EXIT_FAILURE, "Failed to listen with the socket");

    return sock;
}

static void print_hex(uint8_t *data, uint32_t data_len) {
    printf("{");

    for (size_t i = 0; i < data_len; i++)
        if (i != (data_len - 1))
            printf("0x%x, ", data[i]);
        else
            printf("0x%x", data[i]);

    printf("}\n");
}

int main(void) {
    struct sockaddr_in client_addr;
    uint8_t buffer[RECV_MAX];
    ssize_t buf_len;
    int ret;

    socklen_t addr_size = sizeof(client_addr);
    int socket = setup_socket(PORT);

    socket = accept(socket, (struct sockaddr *)&client_addr, &addr_size);
    if (socket == -1)
        err(EXIT_FAILURE, "Failed to accept with the socket");

    buf_len = recv(socket, buffer, RECV_MAX, 0);
    if (buf_len == -1)
        err(EXIT_FAILURE, "Failed to read data from the socket");

    client_hello_t *ch = calloc(1, sizeof(client_hello_t));
    if (ch == NULL)
        errx(EXIT_FAILURE, "out of memory");

    ret = cchello_parse(ch, buffer, buf_len);
    printf("function ret: %d, data size: %ld\n", ret, buf_len);

    printf("tls version: %d\n", ch->version);
    printf("session id: ");
    print_hex(ch->session_id, ch->session_id_len);
    printf("random: ");
    print_hex(ch->random, sizeof(ch->random));
    printf("compression methods: ");
    print_hex(ch->compression_methods, ch->compression_methods_len);
    printf("cipher suites: ");
    print_hex(ch->cipher_suites, ch->cipher_suites_len);
    printf("extensions: ");
    print_hex(ch->extensions, ch->extensions_len);

    return 0;
}
