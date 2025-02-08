#include "unity.h"

extern void test_hash_test_vectors(void);
extern void test_hash_insanely_long_input(void);
extern void test_hash_to_byte_vector(void);

void setUp(void) {
}

void tearDown(void) {
}

// Main function to run the tests
int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_hash_test_vectors);
    RUN_TEST(test_hash_insanely_long_input);
    RUN_TEST(test_hash_to_byte_vector);

    return UNITY_END();
}