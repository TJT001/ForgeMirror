#ifndef FM_AES_H
#define FM_AES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t round_keys[240];
} fm_aes256;

void fm_aes256_init(fm_aes256 *aes, const uint8_t key[32]);
void fm_aes256_encrypt(const fm_aes256 *aes, const uint8_t in[16], uint8_t out[16]);

/* Returns 0 when the tag verifies and the plaintext is written. */
int fm_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t tag[16], uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
