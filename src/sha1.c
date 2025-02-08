#include "sha1.h"
#include <string.h>
#include <stdlib.h>

// Helper function to perform left rotation (circular shift) on a 32-bit word
static uint32_t rot(uint32_t arg, size_t bits) {
    return ((arg << bits) | (arg >> (32 - bits)));
}

// Constant-time memory set function to overwrite memory securely
static void constant_time_memset(uint8_t* data, uint8_t value, size_t length) {
    volatile uint8_t *ptr = data;
    for (size_t i = 0; i < length; ++i) {
        ptr[i] = value;
    }
}

// Helper function to pad data to SHA-1 specification and handle length field
static void pad_data(const uint8_t* data, size_t data_len, uint8_t* padded_data, uint64_t* ml) {
    // Copy data to padded buffer
    memcpy(padded_data, data, data_len);

    // Add the '1' bit (0x80) at the end of the data
    padded_data[data_len] = 0x80;

    // Zero out the rest of the padding
    constant_time_memset(padded_data + data_len + 1, 0, SHA1_BLOCK_SIZE - data_len - 1);

    // If the padding overflows, write the length field at the end of the block
    if (data_len >= SHA1_BLOCK_SIZE - 8) {
        *ml = (uint64_t)data_len * 8;  // Store message length in bits
        memcpy(padded_data + SHA1_BLOCK_SIZE - 8, &*ml, 8);
    }
}

// Function to process a single block of data
static void process_block(const uint32_t* w, uint32_t* h0, uint32_t* h1, uint32_t* h2, uint32_t* h3, uint32_t* h4) {
    uint32_t a = *h0, b = *h1, c = *h2, d = *h3, e = *h4;

    for (size_t i = 0; i < 80; ++i) {
        uint32_t f, k;

        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = rot(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rot(b, 30);
        b = a;
        a = temp;
    }

    *h0 += a;
    *h1 += b;
    *h2 += c;
    *h3 += d;
    *h4 += e;
}

// Function to process the message data in blocks and return the SHA-1 hash
uint8_t* sha1(const uint8_t* data, size_t data_len) {
    // Error handling for invalid input
    if (data == NULL || data_len == 0) {
        return NULL;  // Invalid input
    }

    // Allocate memory for the final hash (20 bytes)
    uint8_t* hash = (uint8_t*)malloc(SHA1_DIGEST_LENGTH);
    if (!hash) {
        return NULL;  // Memory allocation failed
    }

    uint8_t chunk[SHA1_BLOCK_SIZE];
    uint32_t w[80];
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    uint64_t ml = (uint64_t)data_len * 8;  // Message length in bits

    // Process the message in blocks of SHA1_BLOCK_SIZE bytes
    size_t offset = 0;
    while (offset < data_len) {
        size_t remaining = data_len - offset;
        size_t chunk_size = (remaining >= SHA1_BLOCK_SIZE) ? SHA1_BLOCK_SIZE : remaining;

        // Copy the chunk from the input data
        memcpy(chunk, &data[offset], chunk_size);

        // Pad the chunk if it's the final block
        if (remaining < SHA1_BLOCK_SIZE) {
            pad_data(data, data_len, chunk, &ml);
        }

        // Prepare the message schedule (w)
        for (size_t i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)chunk[i * 4 + 0] << 24)
                 | ((uint32_t)chunk[i * 4 + 1] << 16)
                 | ((uint32_t)chunk[i * 4 + 2] << 8)
                 | (uint32_t)chunk[i * 4 + 3];
        }

        // Extend the message schedule
        for (size_t i = 16; i < 80; ++i) {
            w[i] = rot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        // Process the current block
        process_block(w, &h0, &h1, &h2, &h3, &h4);

        // Move to the next block
        offset += SHA1_BLOCK_SIZE;
    }

    // Convert the resulting hash to byte array format
    hash[0] = (uint8_t)((h0 >> 24) & 0xff);
    hash[1] = (uint8_t)((h0 >> 16) & 0xff);
    hash[2] = (uint8_t)((h0 >> 8) & 0xff);
    hash[3] = (uint8_t)(h0 & 0xff);
    hash[4] = (uint8_t)((h1 >> 24) & 0xff);
    hash[5] = (uint8_t)((h1 >> 16) & 0xff);
    hash[6] = (uint8_t)((h1 >> 8) & 0xff);
    hash[7] = (uint8_t)(h1 & 0xff);
    hash[8] = (uint8_t)((h2 >> 24) & 0xff);
    hash[9] = (uint8_t)((h2 >> 16) & 0xff);
    hash[10] = (uint8_t)((h2 >> 8) & 0xff);
    hash[11] = (uint8_t)(h2 & 0xff);
    hash[12] = (uint8_t)((h3 >> 24) & 0xff);
    hash[13] = (uint8_t)((h3 >> 16) & 0xff);
    hash[14] = (uint8_t)((h3 >> 8) & 0xff);
    hash[15] = (uint8_t)(h3 & 0xff);
    hash[16] = (uint8_t)((h4 >> 24) & 0xff);
    hash[17] = (uint8_t)((h4 >> 16) & 0xff);
    hash[18] = (uint8_t)((h4 >> 8) & 0xff);
    hash[19] = (uint8_t)(h4 & 0xff);

    return hash;
}
