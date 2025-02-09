#include "sha2.h"
#include <string.h>

// Helper function to rotate 32-bit values right
static uint32_t rot32(uint32_t arg, size_t bits) {
    return (arg >> bits) | (arg << (32 - bits));
}

// Helper function to rotate 64-bit values right
static uint64_t rot64(uint64_t arg, size_t bits) {
    return (arg >> bits) | (arg << (64 - bits));
}

// Internal implementation of SHA-224/256
static void sha224_256_internal(const uint8_t* data, size_t data_len, uint8_t* digest, int is_224) {
    uint8_t chunk[64];
    uint32_t w[64];
    uint32_t h0 = is_224 ? 0xc1059ed8 : 0x6a09e667;
    uint32_t h1 = is_224 ? 0x367cd507 : 0xbb67ae85;
    uint32_t h2 = is_224 ? 0x3070dd17 : 0x3c6ef372;
    uint32_t h3 = is_224 ? 0xf70e5939 : 0xa54ff53a;
    uint32_t h4 = is_224 ? 0xffc00b31 : 0x510e527f;
    uint32_t h5 = is_224 ? 0x68581511 : 0x9b05688c;
    uint32_t h6 = is_224 ? 0x64f98fa7 : 0x1f83d9ab;
    uint32_t h7 = is_224 ? 0xbefa4fa4 : 0x5be0cd19;

    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint64_t ml = (uint64_t)data_len * 8;

    for (size_t offset = 0; offset < data_len + 9; offset += 64) {
        if (offset + 64 <= data_len) {
            memcpy(chunk, data + offset, 64);
        } else {
            memset(chunk, 0, 64);
            if (offset < data_len) {
                memcpy(chunk, data + offset, data_len - offset);
            }
            if (offset <= data_len) {
                chunk[data_len - offset] = 0x80;
            }
            if (offset + 64 - data_len >= 9) {
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
            w[i] = ((uint32_t)chunk[i * 4] << 24) |
                   ((uint32_t)chunk[i * 4 + 1] << 16) |
                   ((uint32_t)chunk[i * 4 + 2] << 8) |
                   (uint32_t)chunk[i * 4 + 3];
        }

        for (size_t i = 16; i < 64; ++i) {
            uint32_t s0 = rot32(w[i-15], 7) ^ rot32(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rot32(w[i-2], 17) ^ rot32(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (size_t i = 0; i < 64; ++i) {
            uint32_t S1 = rot32(e, 6) ^ rot32(e, 11) ^ rot32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rot32(a, 2) ^ rot32(a, 13) ^ rot32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Store hash values
    digest[0] = (uint8_t)(h0 >> 24);
    digest[1] = (uint8_t)(h0 >> 16);
    digest[2] = (uint8_t)(h0 >> 8);
    digest[3] = (uint8_t)h0;
    digest[4] = (uint8_t)(h1 >> 24);
    digest[5] = (uint8_t)(h1 >> 16);
    digest[6] = (uint8_t)(h1 >> 8);
    digest[7] = (uint8_t)h1;
    digest[8] = (uint8_t)(h2 >> 24);
    digest[9] = (uint8_t)(h2 >> 16);
    digest[10] = (uint8_t)(h2 >> 8);
    digest[11] = (uint8_t)h2;
    digest[12] = (uint8_t)(h3 >> 24);
    digest[13] = (uint8_t)(h3 >> 16);
    digest[14] = (uint8_t)(h3 >> 8);
    digest[15] = (uint8_t)h3;
    digest[16] = (uint8_t)(h4 >> 24);
    digest[17] = (uint8_t)(h4 >> 16);
    digest[18] = (uint8_t)(h4 >> 8);
    digest[19] = (uint8_t)h4;
    digest[20] = (uint8_t)(h5 >> 24);
    digest[21] = (uint8_t)(h5 >> 16);
    digest[22] = (uint8_t)(h5 >> 8);
    digest[23] = (uint8_t)h5;
    digest[24] = (uint8_t)(h6 >> 24);
    digest[25] = (uint8_t)(h6 >> 16);
    digest[26] = (uint8_t)(h6 >> 8);
    digest[27] = (uint8_t)h6;

    if (!is_224) {
        digest[28] = (uint8_t)(h7 >> 24);
        digest[29] = (uint8_t)(h7 >> 16);
        digest[30] = (uint8_t)(h7 >> 8);
        digest[31] = (uint8_t)h7;
    }
}

static void sha384_512_internal(const uint8_t* data, size_t data_len, uint8_t* digest,
                              size_t digest_len, const uint64_t* initial_hash) {
    uint8_t chunk[128];
    uint64_t w[80];
    uint64_t h0 = initial_hash[0];
    uint64_t h1 = initial_hash[1];
    uint64_t h2 = initial_hash[2];
    uint64_t h3 = initial_hash[3];
    uint64_t h4 = initial_hash[4];
    uint64_t h5 = initial_hash[5];
    uint64_t h6 = initial_hash[6];
    uint64_t h7 = initial_hash[7];

    static const uint64_t k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    uint64_t ml = (uint64_t)data_len * 8;

    for (size_t offset = 0; offset < data_len + 17; offset += 128) {
        if (offset + 128 <= data_len) {
            memcpy(chunk, data + offset, 128);
        } else {
            memset(chunk, 0, 128);
            if (offset < data_len) {
                memcpy(chunk, data + offset, data_len - offset);
            }
            if (offset <= data_len) {
                chunk[data_len - offset] = 0x80;
            }
            if (offset + 128 - data_len >= 17) {
                chunk[120] = (uint8_t)(ml >> 56);
                chunk[121] = (uint8_t)(ml >> 48);
                chunk[122] = (uint8_t)(ml >> 40);
                chunk[123] = (uint8_t)(ml >> 32);
                chunk[124] = (uint8_t)(ml >> 24);
                chunk[125] = (uint8_t)(ml >> 16);
                chunk[126] = (uint8_t)(ml >> 8);
                chunk[127] = (uint8_t)ml;
            }
        }

        for (size_t i = 0; i < 16; ++i) {
            w[i] = ((uint64_t)chunk[i * 8] << 56) |
                   ((uint64_t)chunk[i * 8 + 1] << 48) |
                   ((uint64_t)chunk[i * 8 + 2] << 40) |
                   ((uint64_t)chunk[i * 8 + 3] << 32) |
                   ((uint64_t)chunk[i * 8 + 4] << 24) |
                   ((uint64_t)chunk[i * 8 + 5] << 16) |
                   ((uint64_t)chunk[i * 8 + 6] << 8) |
                   (uint64_t)chunk[i * 8 + 7];
        }

        for (size_t i = 16; i < 80; ++i) {
            uint64_t s0 = rot64(w[i-15], 1) ^ rot64(w[i-15], 8) ^ (w[i-15] >> 7);
            uint64_t s1 = rot64(w[i-2], 19) ^ rot64(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint64_t a = h0;
        uint64_t b = h1;
        uint64_t c = h2;
        uint64_t d = h3;
        uint64_t e = h4;
        uint64_t f = h5;
        uint64_t g = h6;
        uint64_t h = h7;

        for (size_t i = 0; i < 80; ++i) {
            uint64_t S1 = rot64(e, 14) ^ rot64(e, 18) ^ rot64(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t temp1 = h + S1 + ch + k[i] + w[i];
            uint64_t S0 = rot64(a, 28) ^ rot64(a, 34) ^ rot64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Store the hash result
    size_t pos = 0;
    for (size_t i = 0; i < digest_len && pos < digest_len; i += 8) {
        uint64_t h = 0;
        switch (i / 8) {
            case 0: h = h0; break;
            case 1: h = h1; break;
            case 2: h = h2; break;
            case 3: h = h3; break;
            case 4: h = h4; break;
            case 5: h = h5; break;
            case 6: h = h6; break;
            case 7: h = h7; break;
        }

        size_t remaining = digest_len - pos;
        size_t bytes = (remaining >= 8) ? 8 : remaining;

        for (size_t j = 0; j < bytes; j++) {
            digest[pos++] = (uint8_t)(h >> (56 - j * 8));
        }
    }
}

// Helper function to calculate SHA-512/t initialization vector
static void sha512_iv(const char* variant_string, uint64_t* iv) {
    // Initial state for SHA-512 with XOR mask
    static const uint64_t SHA512_IV_MASKED[8] = {
        0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5,
        0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5,
        0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5,
        0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5,
        0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5,
        0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5,
        0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5,
        0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5
    };

    // Calculate the initialization vector using SHA-512
    uint8_t temp_digest[64];
    size_t str_len = strlen(variant_string);
    sha384_512_internal((const uint8_t*)variant_string, str_len, temp_digest, 64, SHA512_IV_MASKED);

    // Convert the digest to uint64_t array
    for (int i = 0; i < 8; i++) {
        iv[i] = ((uint64_t)temp_digest[i * 8] << 56) |
                ((uint64_t)temp_digest[i * 8 + 1] << 48) |
                ((uint64_t)temp_digest[i * 8 + 2] << 40) |
                ((uint64_t)temp_digest[i * 8 + 3] << 32) |
                ((uint64_t)temp_digest[i * 8 + 4] << 24) |
                ((uint64_t)temp_digest[i * 8 + 5] << 16) |
                ((uint64_t)temp_digest[i * 8 + 6] << 8) |
                (uint64_t)temp_digest[i * 8 + 7];
    }
}

// Public API implementations
void sha224_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    sha224_256_internal(data, data_len, digest, 1);
}

void sha256_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    sha224_256_internal(data, data_len, digest, 0);
}

void sha384_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    static const uint64_t SHA384_IV[8] = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
        0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    sha384_512_internal(data, data_len, digest, 48, SHA384_IV);
}

void sha512_224_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    uint64_t iv[8];
    sha512_iv("SHA-512/224", iv);
    sha384_512_internal(data, data_len, digest, 28, iv);
}

void sha512_256_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    uint64_t iv[8];
    sha512_iv("SHA-512/256", iv);
    sha384_512_internal(data, data_len, digest, 32, iv);
}

void sha512_hash(const uint8_t* data, size_t data_len, uint8_t* digest) {
    static const uint64_t SHA512_IV[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };
    sha384_512_internal(data, data_len, digest, 64, SHA512_IV);
}
