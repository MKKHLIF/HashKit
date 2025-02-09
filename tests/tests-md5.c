#include "unity.h"
#include "md5.h"
#include <string.h>

typedef struct {
    const char *input;
    const char *expected_output;
} TestVector;

void test_Md5_HashTestVectors(void) {
    TestVector testVectors[] = {
        {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
        {"The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0"},
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); ++i) {
        uint8_t result[MD5_DIGEST_LENGTH];
        Md5((const uint8_t *)testVectors[i].input, strlen(testVectors[i].input), result);

        // Convert result into a hex string
        char resultHex[MD5_DIGEST_LENGTH * 2 + 1];
        for (size_t j = 0; j < MD5_DIGEST_LENGTH; ++j) {
            snprintf(&resultHex[j * 2], 3, "%02x", result[j]);
        }

        // Compare the MD5 hash output with the expected output
        TEST_ASSERT_EQUAL_STRING(testVectors[i].expected_output, resultHex);
    }
}
