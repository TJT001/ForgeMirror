#include "fm_aes.h"

#include <string.h>

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t xtime(uint8_t value) {
    return (uint8_t) ((value << 1) ^ (((value >> 7) & 1) * 0x1b));
}

static void add_round_key(uint8_t state[16], const uint8_t *round) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round[i];
    }
}

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp[16];
    memcpy(tmp, state, 16);
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row + 4 * col] = tmp[row + 4 * ((col + row) & 3)];
        }
    }
}

static void mix_columns(uint8_t state[16]) {
    for (int col = 0; col < 4; col++) {
        uint8_t *c = state + col * 4;
        uint8_t a = c[0];
        uint8_t b = c[1];
        uint8_t d = c[2];
        uint8_t e = c[3];
        uint8_t a2 = xtime(a);
        uint8_t b2 = xtime(b);
        uint8_t d2 = xtime(d);
        uint8_t e2 = xtime(e);
        c[0] = (uint8_t) (a2 ^ (b2 ^ b) ^ d ^ e);
        c[1] = (uint8_t) (a ^ b2 ^ (d2 ^ d) ^ e);
        c[2] = (uint8_t) (a ^ b ^ d2 ^ (e2 ^ e));
        c[3] = (uint8_t) ((a2 ^ a) ^ b ^ d ^ e2);
    }
}

void fm_aes256_init(fm_aes256 *aes, const uint8_t key[32]) {
    memcpy(aes->round_keys, key, 32);
    uint8_t rcon = 1;
    for (int word = 8; word < 60; word++) {
        uint8_t temp[4];
        memcpy(temp, aes->round_keys + (word - 1) * 4, 4);
        if (word % 8 == 0) {
            uint8_t first = temp[0];
            temp[0] = SBOX[temp[1]] ^ rcon;
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[first];
            rcon = xtime(rcon);
        } else if (word % 8 == 4) {
            for (int i = 0; i < 4; i++) {
                temp[i] = SBOX[temp[i]];
            }
        }
        for (int i = 0; i < 4; i++) {
            aes->round_keys[word * 4 + i] =
                    aes->round_keys[(word - 8) * 4 + i] ^ temp[i];
        }
    }
}

void fm_aes256_encrypt(const fm_aes256 *aes, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    add_round_key(state, aes->round_keys);
    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, aes->round_keys + round * 16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, aes->round_keys + 14 * 16);
    memcpy(out, state, 16);
}

typedef struct {
    uint64_t hi[16][256];
    uint64_t lo[16][256];
} ghash_table;

static void ghash_init(ghash_table *table, uint64_t h_hi, uint64_t h_lo) {
    uint64_t pow_hi[128];
    uint64_t pow_lo[128];
    pow_hi[0] = h_hi;
    pow_lo[0] = h_lo;
    for (int bit = 1; bit < 128; bit++) {
        uint64_t carry = pow_lo[bit - 1] & 1;
        pow_lo[bit] = (pow_lo[bit - 1] >> 1) | (pow_hi[bit - 1] << 63);
        pow_hi[bit] = (pow_hi[bit - 1] >> 1)
                      ^ ((uint64_t) 0xe100000000000000ull * carry);
    }
    for (int pos = 0; pos < 16; pos++) {
        for (int value = 0; value < 256; value++) {
            uint64_t hi = 0;
            uint64_t lo = 0;
            for (int bit = 0; bit < 8; bit++) {
                if (value & (1 << bit)) {
                    int index = pos * 8 + (7 - bit);
                    hi ^= pow_hi[index];
                    lo ^= pow_lo[index];
                }
            }
            table->hi[pos][value] = hi;
            table->lo[pos][value] = lo;
        }
    }
}

static void ghash_update(uint64_t *hi, uint64_t *lo, const ghash_table *table,
                         const uint8_t *data, size_t len) {
    uint8_t block[16];
    while (len > 0) {
        size_t take = len < 16 ? len : 16;
        memset(block, 0, sizeof(block));
        memcpy(block, data, take);
        uint8_t mixed[16];
        for (int pos = 0; pos < 16; pos++) {
            uint8_t current = pos < 8
                              ? (uint8_t) (*hi >> (56 - pos * 8))
                              : (uint8_t) (*lo >> (56 - (pos - 8) * 8));
            mixed[pos] = (uint8_t) (block[pos] ^ current);
        }
        uint64_t next_hi = 0;
        uint64_t next_lo = 0;
        for (int pos = 0; pos < 16; pos++) {
            next_hi ^= table->hi[pos][mixed[pos]];
            next_lo ^= table->lo[pos][mixed[pos]];
        }
        *hi = next_hi;
        *lo = next_lo;
        data += take;
        len -= take;
    }
}

int fm_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t tag[16], uint8_t *plaintext) {
    fm_aes256 aes;
    fm_aes256_init(&aes, key);
    uint8_t h_block[16] = {0};
    fm_aes256_encrypt(&aes, h_block, h_block);
    uint64_t h_hi = 0;
    uint64_t h_lo = 0;
    for (int i = 0; i < 8; i++) {
        h_hi = (h_hi << 8) | h_block[i];
        h_lo = (h_lo << 8) | h_block[i + 8];
    }

    ghash_table table;
    ghash_init(&table, h_hi, h_lo);
    uint64_t acc_hi = 0;
    uint64_t acc_lo = 0;
    ghash_update(&acc_hi, &acc_lo, &table, aad, aad_len);
    ghash_update(&acc_hi, &acc_lo, &table, ciphertext, ciphertext_len);
    uint8_t lengths[16];
    uint64_t aad_bits = (uint64_t) aad_len * 8;
    uint64_t ct_bits = (uint64_t) ciphertext_len * 8;
    for (int i = 0; i < 8; i++) {
        lengths[i] = (uint8_t) (aad_bits >> (56 - i * 8));
        lengths[i + 8] = (uint8_t) (ct_bits >> (56 - i * 8));
    }
    ghash_update(&acc_hi, &acc_lo, &table, lengths, 16);

    uint8_t j0[16];
    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
    uint8_t mask[16];
    fm_aes256_encrypt(&aes, j0, mask);
    uint8_t expected[16];
    for (int i = 0; i < 8; i++) {
        expected[i] = (uint8_t) (acc_hi >> (56 - i * 8)) ^ mask[i];
        expected[i + 8] = (uint8_t) (acc_lo >> (56 - i * 8)) ^ mask[i + 8];
    }
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (uint8_t) (expected[i] ^ tag[i]);
    }
    if (diff != 0) {
        return -1;
    }

    uint8_t counter[16];
    memcpy(counter, j0, 16);
    size_t offset = 0;
    while (offset < ciphertext_len) {
        for (int i = 15; i >= 12; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break;
            }
        }
        uint8_t stream[16];
        fm_aes256_encrypt(&aes, counter, stream);
        size_t take = ciphertext_len - offset;
        if (take > 16) {
            take = 16;
        }
        for (size_t i = 0; i < take; i++) {
            plaintext[offset + i] = ciphertext[offset + i] ^ stream[i];
        }
        offset += take;
    }
    return 0;
}
