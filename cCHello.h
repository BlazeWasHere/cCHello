//          Copyright Blaze 2021.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#ifndef _CCHELLO_H
#define _CCHELLO_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define TLS_VERSION_NUMBER(id)                                                 \
    ((((id##_VERSION_MAJOR) & 0xFF) << 8) | ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_0_VERSION_MAJOR 0x3
#define TLS_1_0_VERSION_MINOR 0x1

#define TLS_1_1_VERSION_MAJOR 0x3
#define TLS_1_1_VERSION_MINOR 0x2

#define TLS_1_2_VERSION_MAJOR 0x3
#define TLS_1_2_VERSION_MINOR 0x3

#define TLS_1_3_VERSION_MAJOR 0x3
#define TLS_1_3_VERSION_MINOR 0x4

enum tls_version {
    UNKNOWN = -1,
    TLS_1_0 = TLS_VERSION_NUMBER(TLS_1_0),
    TLS_1_1 = TLS_VERSION_NUMBER(TLS_1_1),
    TLS_1_2 = TLS_VERSION_NUMBER(TLS_1_2),
    TLS_1_3 = TLS_VERSION_NUMBER(TLS_1_3),
};

enum cchello_err {
    /* The packet given is not a handshake record or a client hello. */
    CCHELLO_WRONG_PACKET = -1,
    /* An overflow/overstep would have occured. */
    CCHELLO_OVERFLOW = -2,
    /* Not enough memory. */
    CCHELLO_NOMEM = -3,
};

typedef struct {
    /* The client's TLS version */
    enum tls_version version;
    /*  The client provides 32 bytes of random data. This data will be used
     * later in the session. In this example we've made the random data a
     * predictable string. */
    uint8_t random[32];
    /* The client can provide the ID of a previous TLS session against this
     * server which it is able to resume. */
    uint8_t *session_id;
    uint8_t session_id_len;
    /*  The client provides an ordered list of which cryptographic methods it
     * will support for key exchange, encryption with that exchanged key, and
     * message authentication. The list is in the order preferred by the client,
     * with highest preference first. */
    uint8_t *cipher_suites;
    uint32_t cipher_suites_len;
    /*  The client provides an ordered list of which compression methods it will
     * support. This compression would be applied before encryption (as
     * encrypted data is usually incompressible). */
    uint8_t *compression_methods;
    uint8_t compression_methods_len;
    /*  The client has provided a list of optional extensions which the server
     * can use to take action or enable new features. */
    uint8_t *extensions;
    uint32_t extensions_len;
} client_hello_t;

enum tls_version cchello_parse_version(uint8_t major, uint8_t minor);

/* if <0, error; else returns bytes read from `data` */
int cchello_parse(client_hello_t *ch, uint8_t *data, size_t data_len);

client_hello_t *cchello_client_hello_init(void);

void cchello_client_hello_free(client_hello_t *ch);

#ifdef __cplusplus
}
#endif

#endif // _CCHELLO_H
