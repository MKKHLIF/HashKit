#include "sha1.h"

#include "sha1.h"
#include <string.h>

/* SHA1 round constants */
#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

/* Rotate left operation */
#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* SHA1 round functions */
#define F1(b,c,d) (((b) & (c)) | ((~(b)) & (d)))
#define F2(b,c,d) ((b) ^ (c) ^ (d))
#define F3(b,c,d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F4(b,c,d) ((b) ^ (c) ^ (d))

/* Process one block of data */
static void SHA1_Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t block[80];
    int i;

    /* Copy buffer into block array */
    for (i = 0; i < 16; i++) {
        block[i] = (buffer[4*i] << 24) |
                   (buffer[4*i+1] << 16) |
                   (buffer[4*i+2] << 8) |
                   (buffer[4*i+3]);
    }

    /* Extend the block array */
    for (i = 16; i < 80; i++) {
        block[i] = ROL(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    /* Initialize working variables */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Main loop */
    for (i = 0; i < 80; i++) {
        uint32_t temp;
        if (i < 20) {
            temp = ROL(a, 5) + F1(b,c,d) + e + block[i] + K1;
        } else if (i < 40) {
            temp = ROL(a, 5) + F2(b,c,d) + e + block[i] + K2;
        } else if (i < 60) {
            temp = ROL(a, 5) + F3(b,c,d) + e + block[i] + K3;
        } else {
            temp = ROL(a, 5) + F4(b,c,d) + e + block[i] + K4;
        }
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = temp;
    }

    /* Update state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

int SHA1_Init(SHA1_CTX *ctx) {
    if (!ctx) return -1;

    /* Initialize hash values */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    ctx->count = 0;
    memset(ctx->buffer, 0, SHA1_BLOCK_SIZE);

    return 0;
}

int SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len) {
    if (!ctx || !data) return -1;

    const unsigned char *input = (const unsigned char*)data;
    size_t i;

    /* Process existing buffer first */
    size_t buffer_used = (ctx->count / 8) % SHA1_BLOCK_SIZE;
    if (buffer_used > 0) {
        size_t space_left = SHA1_BLOCK_SIZE - buffer_used;
        size_t to_copy = (len < space_left) ? len : space_left;

        memcpy(&ctx->buffer[buffer_used], input, to_copy);
        ctx->count += to_copy * 8;
        input += to_copy;
        len -= to_copy;

        if (buffer_used + to_copy == SHA1_BLOCK_SIZE) {
            SHA1_Transform(ctx->state, ctx->buffer);
        }
    }

    /* Process full blocks */
    while (len >= SHA1_BLOCK_SIZE) {
        SHA1_Transform(ctx->state, input);
        ctx->count += SHA1_BLOCK_SIZE * 8;
        input += SHA1_BLOCK_SIZE;
        len -= SHA1_BLOCK_SIZE;
    }

    /* Store remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, input, len);
        ctx->count += len * 8;
    }

    return 0;
}

int SHA1_Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx) {
    if (!ctx || !digest) return -1;

    unsigned char finalcount[8];
    int i;

    /* Store count in big-endian format */
    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((ctx->count >> ((7 - i) * 8)) & 255);
    }

    /* Pad with 1 bit followed by zeros */
    SHA1_Update(ctx, (unsigned char *)"\x80", 1);

    /* Pad with zeros to leave room for length */
    while ((ctx->count / 8) % SHA1_BLOCK_SIZE != 56) {
        SHA1_Update(ctx, (unsigned char *)"\0", 1);
    }

    /* Append length */
    SHA1_Update(ctx, finalcount, 8);

    /* Copy final state to digest */
    for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        digest[i] = (unsigned char)
            ((ctx->state[i/4] >> ((3 - (i % 4)) * 8)) & 255);
    }

    /* Clear sensitive information */
    memset(ctx, 0, sizeof(SHA1_CTX));

    return 0;
}

int SHA1(const void *data, size_t len, unsigned char digest[SHA1_DIGEST_LENGTH]) {
    SHA1_CTX ctx;
    int ret;

    ret = SHA1_Init(&ctx);
    if (ret != 0) return ret;

    ret = SHA1_Update(&ctx, data, len);
    if (ret != 0) return ret;

    ret = SHA1_Final(digest, &ctx);
    return ret;
}