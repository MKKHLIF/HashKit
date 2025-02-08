#ifndef HASH_SHA1_H
#define HASH_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20  // 160 bits = 20 bytes

/**
 * This function computes the SHA-1 message digest of the given data.
 *
 * @param[in] data
 *     This is the data for which to compute the message digest.
 * @param[in] data_len
 *     The length of the input data.
 *
 * @return
 *     The SHA1 message digest of the given data is returned as a pointer to an array of bytes.
 *     The caller must free the returned memory after use.
 */
uint8_t* sha1(const uint8_t* data, size_t data_len);

#endif /* HASH_SHA1_H */
