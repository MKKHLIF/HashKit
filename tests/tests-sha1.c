#include <unity.h>
#include "sha1.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// https://www.di-mgt.com.au/sha_testvectors.html
void test_hash_test_vectors(void) {
    struct TestVector {
        const char* input;
        const uint8_t output[SHA1_DIGEST_LENGTH];
    };

    // https://www.di-mgt.com.au/sha_testvectors.html
    struct TestVector testVectors[] = {
        {"abc", {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d}},
        {"", {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
              0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         {0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
          0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1}},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         {0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19,
          0xf9, 0x95, 0xb6, 0x70, 0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59}},
        {  // Large input of 1 million 'a' characters
          "a", {0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e,
               0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f}
        }
    };

    // Test each vector
    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); ++i) {
        uint8_t* result = sha1((uint8_t*)testVectors[i].input, strlen(testVectors[i].input));
        TEST_ASSERT_NOT_NULL(result);

        // Check if result matches the expected output
        for (int j = 0; j < SHA1_DIGEST_LENGTH; ++j) {
            TEST_ASSERT_EQUAL_UINT8(testVectors[i].output[j], result[j]);
        }

        // Free allocated memory for the hash result
        free(result);
    }
}

// Test for large input (insanely long test vector)
void test_hash_insanely_long_input(void) {
    const char* baseString = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    size_t repeat_count = 16777216;
    size_t input_length = strlen(baseString) * repeat_count;
    char* long_input = malloc(input_length + 1);
    TEST_ASSERT_NOT_NULL(long_input);

    for (size_t i = 0; i < repeat_count; ++i) {
        memcpy(long_input + i * strlen(baseString), baseString, strlen(baseString));
    }
    long_input[input_length] = '\0';  // Null-terminate the string

    uint8_t* result = sha1((uint8_t*)long_input, input_length);
    TEST_ASSERT_NOT_NULL(result);

    uint8_t expected_hash[SHA1_DIGEST_LENGTH] = {0x77, 0x89, 0xf0, 0xc9, 0xef, 0x7b, 0xfc, 0x40, 0xd9, 0x33,
                                                 0x11, 0x14, 0x3d, 0xfb, 0xe6, 0x9e, 0x20, 0x17, 0xf5, 0x92};

    // Compare the expected result with the computed hash
    for (int i = 0; i < SHA1_DIGEST_LENGTH; ++i) {
        TEST_ASSERT_EQUAL_UINT8(expected_hash[i], result[i]);
    }

    // Free allocated memory
    free(long_input);
    free(result);
}

// Test to convert hash to byte vector (similar to StringToBytes in the original tests)
void test_hash_to_byte_vector(void) {
    const char* input = "abc";
    uint8_t* result = sha1((uint8_t*)input, strlen(input));
    TEST_ASSERT_NOT_NULL(result);

    uint8_t expected_result[SHA1_DIGEST_LENGTH] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                                  0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};

    // Compare the result with the expected byte array
    for (int i = 0; i < SHA1_DIGEST_LENGTH; ++i) {
        TEST_ASSERT_EQUAL_UINT8(expected_result[i], result[i]);
    }

    // Free allocated memory
    free(result);
}

