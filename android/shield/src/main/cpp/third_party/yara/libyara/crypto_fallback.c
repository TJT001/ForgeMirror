/* Minimal MD5 fallback for builds without OpenSSL/CommonCrypto/WinCrypt. */
#include <stdint.h>
#include <string.h>

#include "crypto.h"

static const uint32_t FM_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t FM_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static uint32_t fm_rotl(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32 - count));
}

static void fm_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t m[16];
    for (int index = 0; index < 16; index++) {
        m[index] = (uint32_t) block[index * 4]
                 | ((uint32_t) block[index * 4 + 1] << 8)
                 | ((uint32_t) block[index * 4 + 2] << 16)
                 | ((uint32_t) block[index * 4 + 3] << 24);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (int index = 0; index < 64; index++) {
        uint32_t f;
        int g;
        if (index < 16) {
            f = (b & c) | (~b & d);
            g = index;
        } else if (index < 32) {
            f = (d & b) | (~d & c);
            g = (5 * index + 1) % 16;
        } else if (index < 48) {
            f = b ^ c ^ d;
            g = (3 * index + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * index) % 16;
        }
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + fm_rotl(a + f + FM_K[index] + m[g], FM_S[index]);
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void yr_md5_fallback_init(yr_md5_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void yr_md5_fallback_update(yr_md5_ctx *ctx, const void *data, size_t length) {
    const uint8_t *input = (const uint8_t *) data;
    size_t buffered = (size_t) (ctx->count & 0x3f);
    ctx->count += length;
    if (buffered != 0) {
        size_t need = 64 - buffered;
        if (length < need) {
            memcpy(ctx->buffer + buffered, input, length);
            return;
        }
        memcpy(ctx->buffer + buffered, input, need);
        fm_transform(ctx->state, ctx->buffer);
        input += need;
        length -= need;
    }
    while (length >= 64) {
        fm_transform(ctx->state, input);
        input += 64;
        length -= 64;
    }
    if (length > 0) {
        memcpy(ctx->buffer, input, length);
    }
}

void yr_md5_fallback_final(uint8_t digest[16], yr_md5_ctx *ctx) {
    uint64_t bits = ctx->count * 8;
    uint8_t padding[72];
    size_t buffered = (size_t) (ctx->count & 0x3f);
    size_t pad = buffered < 56 ? (56 - buffered) : (120 - buffered);
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    for (int index = 0; index < 8; index++) {
        padding[pad + index] = (uint8_t) (bits >> (8 * index));
    }
    yr_md5_fallback_update(ctx, padding, pad + 8);
    for (int index = 0; index < 4; index++) {
        digest[index * 4] = (uint8_t) ctx->state[index];
        digest[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 8);
        digest[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 16);
        digest[index * 4 + 3] = (uint8_t) (ctx->state[index] >> 24);
    }
}

/* ---- SHA-1 ---- */
static uint32_t fm_rol(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32 - count));
}

static void fm_sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int index = 0; index < 16; index++) {
        w[index] = ((uint32_t) block[index * 4] << 24)
                 | ((uint32_t) block[index * 4 + 1] << 16)
                 | ((uint32_t) block[index * 4 + 2] << 8)
                 | (uint32_t) block[index * 4 + 3];
    }
    for (int index = 16; index < 80; index++) {
        w[index] = fm_rol(w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], 1);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int index = 0; index < 80; index++) {
        uint32_t f, k;
        if (index < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (index < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (index < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        uint32_t temp = fm_rol(a, 5) + f + e + k + w[index];
        e = d; d = c; c = fm_rol(b, 30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void yr_sha1_fallback_init(yr_sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void yr_sha1_fallback_update(yr_sha1_ctx *ctx, const void *data, size_t length) {
    const uint8_t *input = (const uint8_t *) data;
    size_t buffered = (size_t) (ctx->count & 0x3f);
    ctx->count += length;
    if (buffered != 0) {
        size_t need = 64 - buffered;
        if (length < need) { memcpy(ctx->buffer + buffered, input, length); return; }
        memcpy(ctx->buffer + buffered, input, need);
        fm_sha1_transform(ctx->state, ctx->buffer);
        input += need; length -= need;
    }
    while (length >= 64) { fm_sha1_transform(ctx->state, input); input += 64; length -= 64; }
    if (length > 0) memcpy(ctx->buffer, input, length);
}

void yr_sha1_fallback_final(uint8_t digest[20], yr_sha1_ctx *ctx) {
    uint64_t bits = ctx->count * 8;
    uint8_t padding[72];
    size_t buffered = (size_t) (ctx->count & 0x3f);
    size_t pad = buffered < 56 ? (56 - buffered) : (120 - buffered);
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    for (int index = 0; index < 8; index++) {
        padding[pad + index] = (uint8_t) (bits >> (56 - 8 * index));
    }
    yr_sha1_fallback_update(ctx, padding, pad + 8);
    for (int index = 0; index < 5; index++) {
        digest[index * 4] = (uint8_t) (ctx->state[index] >> 24);
        digest[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 16);
        digest[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 8);
        digest[index * 4 + 3] = (uint8_t) ctx->state[index];
    }
}

/* ---- SHA-256 ---- */
static const uint32_t FM_SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t fm_rotr(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

static void fm_sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int index = 0; index < 16; index++) {
        w[index] = ((uint32_t) block[index * 4] << 24)
                 | ((uint32_t) block[index * 4 + 1] << 16)
                 | ((uint32_t) block[index * 4 + 2] << 8)
                 | (uint32_t) block[index * 4 + 3];
    }
    for (int index = 16; index < 64; index++) {
        uint32_t s0 = fm_rotr(w[index - 15], 7) ^ fm_rotr(w[index - 15], 18)
                    ^ (w[index - 15] >> 3);
        uint32_t s1 = fm_rotr(w[index - 2], 17) ^ fm_rotr(w[index - 2], 19)
                    ^ (w[index - 2] >> 10);
        w[index] = w[index - 16] + s0 + w[index - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int index = 0; index < 64; index++) {
        uint32_t s1 = fm_rotr(e, 6) ^ fm_rotr(e, 11) ^ fm_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + FM_SHA256_K[index] + w[index];
        uint32_t s0 = fm_rotr(a, 2) ^ fm_rotr(a, 13) ^ fm_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void yr_sha256_fallback_init(yr_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void yr_sha256_fallback_update(yr_sha256_ctx *ctx, const void *data, size_t length) {
    const uint8_t *input = (const uint8_t *) data;
    size_t buffered = (size_t) (ctx->count & 0x3f);
    ctx->count += length;
    if (buffered != 0) {
        size_t need = 64 - buffered;
        if (length < need) { memcpy(ctx->buffer + buffered, input, length); return; }
        memcpy(ctx->buffer + buffered, input, need);
        fm_sha256_transform(ctx->state, ctx->buffer);
        input += need; length -= need;
    }
    while (length >= 64) { fm_sha256_transform(ctx->state, input); input += 64; length -= 64; }
    if (length > 0) memcpy(ctx->buffer, input, length);
}

void yr_sha256_fallback_final(uint8_t digest[32], yr_sha256_ctx *ctx) {
    uint64_t bits = ctx->count * 8;
    uint8_t padding[72];
    size_t buffered = (size_t) (ctx->count & 0x3f);
    size_t pad = buffered < 56 ? (56 - buffered) : (120 - buffered);
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    for (int index = 0; index < 8; index++) {
        padding[pad + index] = (uint8_t) (bits >> (56 - 8 * index));
    }
    yr_sha256_fallback_update(ctx, padding, pad + 8);
    for (int index = 0; index < 8; index++) {
        digest[index * 4] = (uint8_t) (ctx->state[index] >> 24);
        digest[index * 4 + 1] = (uint8_t) (ctx->state[index] >> 16);
        digest[index * 4 + 2] = (uint8_t) (ctx->state[index] >> 8);
        digest[index * 4 + 3] = (uint8_t) ctx->state[index];
    }
}
