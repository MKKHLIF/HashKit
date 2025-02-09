#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_LENGTH 16

/**
 * This function computes the MD5 message digest of the given data.
 *
 * @param[in] data
 *     This is the data for which to compute the message digest.
 *
 * @param[in] data_len
 *     The length of the data to process.
 *
 * @param[out] result
 *     The MD5 message digest of the given data is returned in the result
 *     buffer, which should be at least 16 bytes long.
 */
void Md5(const uint8_t *data, size_t data_len, uint8_t *result);

#endif /* MD5_H */
