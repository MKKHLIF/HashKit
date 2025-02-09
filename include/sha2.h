
#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

/**
 * This is the block size, in bytes, used by the SHA-224 hash function.
 */
#define SHA224_BLOCK_SIZE 64

/**
 * This is the block size, in bytes, used by the SHA-256 hash function.
 */
#define SHA256_BLOCK_SIZE 64

/**
 * This is the block size, in bytes, used by the SHA-512 hash function.
 */
#define SHA512_BLOCK_SIZE 128

/**
 * This function computes the SHA-224 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (28 bytes)
 */
void sha224_hash(const uint8_t* data, size_t data_len, uint8_t* digest);

/**
 * This function computes the SHA-256 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (32 bytes)
 */
void sha256_hash(const uint8_t* data, size_t data_len, uint8_t* digest);

/**
 * This function computes the SHA-384 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (48 bytes)
 */
void sha384_hash(const uint8_t* data, size_t data_len, uint8_t* digest);

/**
 * This function computes the SHA-512/224 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (28 bytes)
 */
void sha512_224_hash(const uint8_t* data, size_t data_len, uint8_t* digest);

/**
 * This function computes the SHA-512/256 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (32 bytes)
 */
void sha512_256_hash(const uint8_t* data, size_t data_len, uint8_t* digest);

/**
 * This function computes the SHA-512 message digest of the given data.
 *
 * @param[in] data        The data for which to compute the message digest
 * @param[in] data_len    Length of the input data in bytes
 * @param[out] digest     Buffer to store the resulting digest (64 bytes)
 */
void sha512_hash(const uint8_t* data, size_t data_len, uint8_t* digest);


#endif //SHA2_H
