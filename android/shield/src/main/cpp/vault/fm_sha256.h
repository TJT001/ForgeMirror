#ifndef FM_SHA256_H
#define FM_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} fm_sha256_ctx;

void fm_sha256_init(fm_sha256_ctx *ctx);
void fm_sha256_update(fm_sha256_ctx *ctx, const void *data, size_t len);
void fm_sha256_final(fm_sha256_ctx *ctx, uint8_t out[32]);
void fm_sha256(const void *data, size_t len, uint8_t out[32]);

void fm_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
