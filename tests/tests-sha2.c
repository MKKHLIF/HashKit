#include "unity.h"
#include "sha2.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Helper function to convert a hex string to a byte array
void hex_string_to_bytes(const char* hex_string, uint8_t* bytes, size_t byte_len) {
    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex_string + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Helper function to compare two byte arrays
void compare_bytes(const uint8_t* expected, const uint8_t* actual, size_t len, const char* message) {
    for (size_t i = 0; i < len; i++) {
        char msg[100];
        snprintf(msg, sizeof(msg), "%s (byte %zu)", message, i);
        TEST_ASSERT_EQUAL_HEX8(expected[i], actual[i]);
    }
}

// Test cases for SHA-224
void test_sha224_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
        {"The quick brown fox jumps over the lazy dog", "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"},
        {NULL, "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[28];
        uint8_t expected_digest[28];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha224_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha224_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-224 digest mismatch");
    }
}

// Test cases for SHA-256
void test_sha256_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
        {NULL, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[32];
        uint8_t expected_digest[32];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha256_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha256_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-256 digest mismatch");
    }
}

// Test cases for SHA-384
void test_sha384_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
        {"The quick brown fox jumps over the lazy dog", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"},
        {NULL, "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[48];
        uint8_t expected_digest[48];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha384_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha384_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-384 digest mismatch");
    }
}

// Test cases for SHA-512
void test_sha512_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"},
        {NULL, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[64];
        uint8_t expected_digest[64];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha512_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha512_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-512 digest mismatch");
    }
}

// Test cases for SHA-512/224
void test_sha512_224_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"},
        {"The quick brown fox jumps over the lazy dog", "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37"},
        {NULL, "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[28];
        uint8_t expected_digest[28];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha512_224_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha512_224_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-512/224 digest mismatch");
    }
}

// Test cases for SHA-512/256
void test_sha512_256_test_vectors(void) {
    struct TestVector {
        const char* input;
        const char* output;
    };
    const struct TestVector testVectors[] = {
        {"", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
        {"The quick brown fox jumps over the lazy dog", "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d"},
        {NULL, "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"}  // 1,000,000 'a's
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t digest[32];
        uint8_t expected_digest[32];

        if (testVectors[i].input == NULL) {
            // Special case for 1,000,000 'a's
            char* input = malloc(1000000);
            memset(input, 'a', 1000000);
            sha512_256_hash((uint8_t*)input, 1000000, digest);
            free(input);
        } else {
            sha512_256_hash((uint8_t*)testVectors[i].input, strlen(testVectors[i].input), digest);
        }

        hex_string_to_bytes(testVectors[i].output, expected_digest, sizeof(expected_digest));
        compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-512/256 digest mismatch");
    }
}

// Test case for SHA-256 hash to byte vector
void test_sha256_hash_to_byte_vector(void) {
    const uint8_t expected_digest[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    uint8_t digest[32];
    sha256_hash((uint8_t*)"", 0, digest);
    compare_bytes(expected_digest, digest, sizeof(expected_digest), "SHA-256 byte vector mismatch");
}
