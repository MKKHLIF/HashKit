// MIT License
//
// Copyright (c) 2024 MKKHLIF
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// File: sha1.h

#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

/**
 * Block size used by the SHA-1 hash algorithm (in bytes).
 * This is the size of data chunks processed internally by SHA-1.
 */
#define SHA1_BLOCK_SIZE 64

/**
 * Size of the SHA-1 digest output (in bits).
 * The actual digest will be 20 bytes (160 bits) long.
 */
#define SHA1_DIGEST_SIZE 160

/**
 * Size of the SHA-1 digest in bytes (20 bytes).
 */
#define SHA1_DIGEST_LENGTH (SHA1_DIGEST_SIZE / 8)

/**
 * Structure to hold the internal state of an ongoing SHA-1 hash computation.
 * Used for computing hashes incrementally over multiple data chunks.
 */
typedef struct {
    uint32_t state[5];     /* 5 32-bit words of hash state */
    uint64_t count;        /* 64-bit bit count */
    uint8_t buffer[SHA1_BLOCK_SIZE]; /* Input buffer */
} SHA1_CTX;

/**
 * Initialize a new SHA-1 hashing context.
 * Must be called before using the context for hashing.
 *
 * @param ctx Pointer to the SHA-1 context to initialize
 * @return 0 on success, non-zero on failure
 */
int SHA1_Init(SHA1_CTX *ctx);

/**
 * Update the SHA-1 context with new data.
 * Can be called multiple times to hash data incrementally.
 *
 * @param ctx Pointer to the SHA-1 context
 * @param data Pointer to the input data
 * @param len Length of the input data in bytes
 * @return 0 on success, non-zero on failure
 */
int SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len);

/**
 * Finalize the SHA-1 hash computation and get the digest.
 *
 * @param ctx Pointer to the SHA-1 context
 * @param digest Buffer to receive the 20-byte (160-bit) message digest
 * @return 0 on success, non-zero on failure
 */
int SHA1_Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx);

/**
 * One-shot function to compute SHA-1 hash of a memory buffer.
 *
 * @param data Pointer to the input data
 * @param len Length of the input data in bytes
 * @param digest Buffer to receive the 20-byte (160-bit) message digest
 * @return 0 on success, non-zero on failure
 */
int SHA1(const void *data, size_t len, unsigned char digest[SHA1_DIGEST_LENGTH]);

#endif //SHA1_H
