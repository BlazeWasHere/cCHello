//          Copyright Blaze 2021.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <stdlib.h>
#include <string.h>

#include "cCHello.h"

#define OVERFLOW_CHECK(num)                                                    \
    if (num > data_len)                                                        \
        return CCHELLO_OVERFLOW;

static inline uint32_t concat_bytes(uint8_t x, uint8_t y, uint8_t z) {
    return (x << 16) | (y << 8) | z;
}

enum tls_version cchello_parse_version(uint8_t major, uint8_t minor) {
    uint32_t ret = concat_bytes(0, major, minor);

    if (ret == TLS_1_0 || ret == TLS_1_1 || ret == TLS_1_2 || ret == TLS_1_3)
        return ret;

    return UNKNOWN;
}

client_hello_t *cchello_client_hello_init(void) {
    return (client_hello_t *)calloc(1, sizeof(client_hello_t));
}

int cchello_parse(client_hello_t *ch, uint8_t *data, size_t data_len) {
    uint32_t handshake_len, ch_data_len;
    size_t read = 0;

    if (data_len == 0)
        return read;

    for (read = 0; read < data_len; read++) {
        switch (read) {
        case 0:
            // 0x16 = handshake record
            if (data[read] != 0x16)
                return CCHELLO_WRONG_PACKET;
            break;
        case 2:
            ch->version = cchello_parse_version(data[read - 1], data[read]);
            break;
        case 4:
            handshake_len = concat_bytes(0, data[read - 1], data[read]);
            OVERFLOW_CHECK(handshake_len + read)
            break;
        case 5:
            // handshake message type 0x1 = client hello
            if (data[read] != 0x1)
                return CCHELLO_WRONG_PACKET;
            break;
        case 8:
            ch_data_len =
                concat_bytes(data[read - 2], data[read - 1], data[read]);
            OVERFLOW_CHECK(ch_data_len + read)
            break;
        case 11:
            // TODO: what to do with this, is it even needed?
            // cchello_parse_version(data[read - 1], data[read]);
            break;
        case 42:
            memcpy(ch->random, data + 11, 32);
            break;
        case 43:
            // session id
            ch->session_id_len = data[read];
            OVERFLOW_CHECK(ch->session_id_len + read);

            ch->session_id = calloc(sizeof(uint8_t), ch->session_id_len);
            if (ch->session_id == NULL)
                return CCHELLO_NOMEM;

            memcpy(ch->session_id, data + read + 1, ch->session_id_len);
            // +1 byte; for the session_id_len byte
            read += ch->session_id_len + 1;

            // cipher suites
            OVERFLOW_CHECK(read + 1);
            ch->cipher_suites_len = concat_bytes(0, data[read], data[read + 1]);
            OVERFLOW_CHECK(ch->cipher_suites_len + read);

            ch->cipher_suites = calloc(sizeof(uint8_t), ch->cipher_suites_len);
            if (ch->cipher_suites == NULL)
                return CCHELLO_NOMEM;

            // cipher_suites_len takes 2 bytes
            read += 2;
            memcpy(ch->cipher_suites, data + read, ch->cipher_suites_len);
            read += ch->cipher_suites_len;

            // compression methods
            ch->compression_methods_len = data[read];
            OVERFLOW_CHECK(ch->compression_methods_len + read);

            ch->compression_methods =
                calloc(sizeof(uint8_t), ch->cipher_suites_len);
            memcpy(ch->compression_methods, data + read + 1,
                   ch->compression_methods_len);
            read += ch->compression_methods_len + 1;

            // extensions
            OVERFLOW_CHECK(read + 1);
            ch->extensions_len = concat_bytes(0, data[read], data[read + 1]);
            OVERFLOW_CHECK(ch->extensions_len + read);

            ch->extensions = calloc(sizeof(uint8_t), ch->extensions_len);
            if (ch->extensions == NULL)
                return CCHELLO_NOMEM;

            read += 2;
            memcpy(ch->extensions, data + read, ch->extensions_len);
            read += ch->extensions_len;

            return read;
        }
    }

    return read;
}

void cchello_client_hello_free(client_hello_t *ch) {
    free(ch->extensions);
    free(ch->compression_methods);
    free(ch->cipher_suites);
    free(ch->session_id);
    free(ch);

    // prevent segfault from freeing twice
    ch = NULL;
}
