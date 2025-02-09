#include "unity.h"

// Sha1 Tests
extern void test_hash_test_vectors(void);
extern void test_hash_insanely_long_input(void);
extern void test_hash_to_byte_vector(void);

// Sha2 Tests
extern void test_sha224_test_vectors(void);
extern void test_sha256_test_vectors(void);
extern void test_sha384_test_vectors(void);
extern void test_sha512_test_vectors(void);
extern void test_sha512_224_test_vectors(void);
extern void test_sha512_256_test_vectors(void);
extern void test_sha256_hash_to_byte_vector(void);

// MD5 Tests
extern void test_Md5_HashTestVectors(void);

void setUp(void) {
}

void tearDown(void) {
}

// Main function to run the tests
int main(void) {
    UNITY_BEGIN();
    printf("================ SHA1 tests ================\n");
    RUN_TEST(test_hash_test_vectors);
    RUN_TEST(test_hash_insanely_long_input);
    RUN_TEST(test_hash_to_byte_vector);

    printf("================ SHA2 tests ================\n");
    RUN_TEST(test_sha224_test_vectors);
    RUN_TEST(test_sha256_test_vectors);
    RUN_TEST(test_sha384_test_vectors);
    RUN_TEST(test_sha512_test_vectors);
    RUN_TEST(test_sha512_224_test_vectors);
    RUN_TEST(test_sha512_256_test_vectors);
    RUN_TEST(test_sha256_hash_to_byte_vector);

    printf("================ MD5 tests ================\n");
    RUN_TEST(test_Md5_HashTestVectors);

    return UNITY_END();
}