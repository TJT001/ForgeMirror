#ifndef FM_WHITEBOX_H
#define FM_WHITEBOX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FM_WB_KEY_SIZE 32
#define FM_WB_NONCE_SIZE 12

typedef struct {
    const uint8_t *t1;
    const uint8_t *t2;
    const uint8_t *t3;
    const uint8_t *xor_tables;
    const uint8_t *xor_state;
} fm_wb_table;

/* Parses the WBX1 flat table; returns 0 on success. */
int fm_wb_parse(const uint8_t *data, size_t len, fm_wb_table *table);

/* Unwraps a WBK1 content-key blob; returns 0 on success. */
int fm_wb_unwrap(const fm_wb_table *table, const uint8_t *blob, size_t len,
                 uint8_t out[FM_WB_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
