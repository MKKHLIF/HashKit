#include "sha1.h"
#include <string.h>
#include <stdlib.h>

static uint32_t rot(uint32_t arg, size_t bits) {
    return ((arg << bits) | (arg >> (32 - bits)));
}

uint8_t* sha1(const uint8_t* data, size_t data_len) {
    uint8_t chunk[SHA1_BLOCK_SIZE];
    uint32_t w[80];
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    uint64_t ml = (uint64_t)data_len * 8;

    uint8_t* hash = (uint8_t*)malloc(SHA1_DIGEST_LENGTH);

    for (size_t offset = 0; offset < data_len + 9; offset += SHA1_BLOCK_SIZE) {
        if (offset + SHA1_BLOCK_SIZE <= data_len) {
            memcpy(chunk, &data[offset], SHA1_BLOCK_SIZE);
        } else {
            memset(chunk, 0, SHA1_BLOCK_SIZE);
            if (offset < data_len) {
                memcpy(chunk, &data[offset], data_len - offset);
            }
            if (offset <= data_len) {
                chunk[data_len - offset] = 0x80;
            }
            if (offset + SHA1_BLOCK_SIZE - data_len >= 9) {
                chunk[56] = (uint8_t)(ml >> 56);
                chunk[57] = (uint8_t)(ml >> 48);
                chunk[58] = (uint8_t)(ml >> 40);
                chunk[59] = (uint8_t)(ml >> 32);
                chunk[60] = (uint8_t)(ml >> 24);
                chunk[61] = (uint8_t)(ml >> 16);
                chunk[62] = (uint8_t)(ml >> 8);
                chunk[63] = (uint8_t)ml;
            }
        }

        for (size_t i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)chunk[i * 4 + 0] << 24)
                 | ((uint32_t)chunk[i * 4 + 1] << 16)
                 | ((uint32_t)chunk[i * 4 + 2] << 8)
                 | (uint32_t)chunk[i * 4 + 3];
        }

        for (size_t i = 16; i < 80; ++i) {
            w[i] = rot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (size_t i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
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

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

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
