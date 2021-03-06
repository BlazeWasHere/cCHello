//          Copyright Blaze 2021.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cCHello.h"

static uint8_t ch_1_3[] = {
    0x16, 0x03, 0x01, 0x00, 0xca, 0x01, 0x00, 0x00, 0xc6, 0x03, 0x03, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3,
    0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
    0x01, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
    0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66,
    0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0a, 0x00, 0x08,
    0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x14,
    0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x33, 0x00, 0x26,
    0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
    0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51,
    0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
    0x62, 0x54, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x03,
    0x02, 0x03, 0x04};

static uint8_t ch_1_2[] = {
    0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8,
    0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13,
    0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
    0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x58, 0x00, 0x00,
    0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e,
    0x65, 0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00,
    0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06,
    0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12,
    0x00, 0x00};

static void assert_array(uint8_t *x, uint8_t *y, size_t len) {
    assert(memcmp(x, y, sizeof(uint8_t) * len) == 0);
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

static client_hello_t *ch_init() {
    client_hello_t *ch = cchello_client_hello_init();
    if (ch == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(EXIT_FAILURE);
    }

    return ch;
}

static void test_ch_1_3() {
    client_hello_t *ch = ch_init();

    uint8_t c_session_id[] = {0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
                              0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
                              0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                              0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint8_t c_random[] = {0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                          0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t c_ciphers[] = {0x13, 0x1, 0x13, 0x2, 0x13, 0x3};
    uint8_t c_extensions[] = {
        0x0,  0x0,  0x0,  0x18, 0x0,  0x16, 0x0,  0x0,  0x13, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d,
        0x2e, 0x6e, 0x65, 0x74, 0x0,  0xa,  0x0,  0x8,  0x0,  0x6,  0x0,  0x1d,
        0x0,  0x17, 0x0,  0x18, 0x0,  0xd,  0x0,  0x14, 0x0,  0x12, 0x4,  0x3,
        0x8,  0x4,  0x4,  0x1,  0x5,  0x3,  0x8,  0x5,  0x5,  0x1,  0x8,  0x6,
        0x6,  0x1,  0x2,  0x1,  0x0,  0x33, 0x0,  0x26, 0x0,  0x24, 0x0,  0x1d,
        0x0,  0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea,
        0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
        0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54, 0x0,  0x2d,
        0x0,  0x2,  0x1,  0x1,  0x0,  0x2b, 0x0,  0x3,  0x2,  0x3,  0x4};

    printf("TEST: parsing tls1.3 client hello: START.\n");
    int ret = cchello_parse(ch, ch_1_3, sizeof(ch_1_3));
    assert(ret == sizeof(ch_1_3));

    printf("tls version: %d\n", ch->version);
    assert(ch->version == TLS_1_0);

    printf("session id: ");
    print_hex(ch->session_id, ch->session_id_len);
    assert_array(ch->session_id, c_session_id, sizeof(c_session_id));

    printf("random: ");
    print_hex(ch->random, sizeof(ch->random));
    assert_array(ch->random, c_random, sizeof(c_random));

    printf("compression methods: ");
    print_hex(ch->compression_methods, ch->compression_methods_len);
    assert(ch->compression_methods[0] == 0x0);

    printf("cipher suites: ");
    print_hex(ch->cipher_suites, ch->cipher_suites_len);
    assert_array(ch->cipher_suites, c_ciphers, sizeof(c_ciphers));

    printf("extensions: ");
    print_hex(ch->extensions, ch->extensions_len);
    assert_array(ch->extensions, c_extensions, sizeof(c_extensions));

    printf("TEST: parsing tls1.3 client hello: PASSED.\n\n");
    cchello_client_hello_free(ch);
}

static void test_ch_1_2() {
    client_hello_t *ch = ch_init();

    uint8_t c_session_id[] = {};
    uint8_t c_random[] = {0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                          0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t c_ciphers[] = {0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30,
                           0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x9,
                           0xc0, 0x14, 0xc0, 0xa,  0x0,  0x9c, 0x0,  0x9d,
                           0x0,  0x2f, 0x0,  0x35, 0xc0, 0x12, 0x0,  0xa};
    uint8_t c_extensions[] = {
        0x0,  0x0,  0x0,  0x18, 0x0,  0x16, 0x0,  0x0,  0x13, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65,
        0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x0,  0x5,  0x0,  0x5,  0x1,
        0x0,  0x0,  0x0,  0x0,  0x0,  0xa,  0x0,  0xa,  0x0,  0x8,  0x0,
        0x1d, 0x0,  0x17, 0x0,  0x18, 0x0,  0x19, 0x0,  0xb,  0x0,  0x2,
        0x1,  0x0,  0x0,  0xd,  0x0,  0x12, 0x0,  0x10, 0x4,  0x1,  0x4,
        0x3,  0x5,  0x1,  0x5,  0x3,  0x6,  0x1,  0x6,  0x3,  0x2,  0x1,
        0x2,  0x3,  0xff, 0x1,  0x0,  0x1,  0x0,  0x0,  0x12, 0x0,  0x0};

    printf("TEST: parsing tls1.2 client hello: START.\n");
    int ret = cchello_parse(ch, ch_1_2, sizeof(ch_1_2));
    assert(ret == sizeof(ch_1_2));

    printf("tls version: %d\n", ch->version);
    assert(ch->version == TLS_1_0);

    printf("session id: ");
    print_hex(ch->session_id, ch->session_id_len);
    assert_array(ch->session_id, c_session_id, sizeof(c_session_id));

    printf("random: ");
    print_hex(ch->random, sizeof(ch->random));
    assert_array(ch->random, c_random, sizeof(c_random));

    printf("compression methods: ");
    print_hex(ch->compression_methods, ch->compression_methods_len);
    assert(ch->compression_methods[0] == 0x0);

    printf("cipher suites: ");
    print_hex(ch->cipher_suites, ch->cipher_suites_len);
    assert_array(ch->cipher_suites, c_ciphers, sizeof(c_ciphers));

    printf("extensions: ");
    print_hex(ch->extensions, ch->extensions_len);
    assert_array(ch->extensions, c_extensions, sizeof(c_extensions));

    printf("TEST: parsing tls1.2 client hello: PASSED.\n\n");
    cchello_client_hello_free(ch);
}

int main(void) {
    test_ch_1_2();
    test_ch_1_3();

    printf("ALL TESTS PASSED.\n");

    return 0;
}
