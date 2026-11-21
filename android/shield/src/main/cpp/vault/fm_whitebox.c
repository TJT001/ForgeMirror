#include "fm_whitebox.h"

#include <string.h>

#define T1_ROUNDS 2
#define T1_BOXES 16
#define T1_ROWS 256
#define T1_OUT 16
#define T2_ROUNDS 10
#define T2_BOXES 16
#define T2_ROWS 256
#define T2_OUT 4
#define XOR_CASCADES 80
#define XOR_BOXES 3
#define XOR_ROWS 8
#define XOR_STATE_CASCADES 2
#define XOR_STATE_BOXES 15
#define XOR_STATE_ROWS 32

#define T1_BYTES (T1_ROUNDS * T1_BOXES * T1_ROWS * T1_OUT)
#define T2_BYTES (T2_ROUNDS * T2_BOXES * T2_ROWS * T2_OUT)
#define XOR_BYTES (XOR_CASCADES * XOR_BOXES * XOR_ROWS * 256)
#define XOR_STATE_BYTES (XOR_STATE_CASCADES * XOR_STATE_BOXES * XOR_STATE_ROWS * 256)
#define TABLE_BYTES (T1_BYTES + T2_BYTES + T2_BYTES + XOR_BYTES + XOR_STATE_BYTES)
#define TABLE_HEADER 32

#define WBX_MAGIC "WBX1"

static const uint8_t SHIFT_ROWS[16] = {
    0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14,
};

static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

int fm_wb_parse(const uint8_t *data, size_t len, fm_wb_table *table) {
    if (data == NULL || table == NULL || len != TABLE_HEADER + TABLE_BYTES) {
        return -1;
    }
    if (memcmp(data, WBX_MAGIC, 4) != 0 || read_u32(data + 4) != 1) {
        return -1;
    }
    if (read_u32(data + 8) != T1_BYTES || read_u32(data + 12) != T2_BYTES
        || read_u32(data + 16) != T2_BYTES || read_u32(data + 20) != XOR_BYTES
        || read_u32(data + 24) != XOR_STATE_BYTES) {
        return -1;
    }
    const uint8_t *cursor = data + TABLE_HEADER;
    table->t1 = cursor;
    cursor += T1_BYTES;
    table->t2 = cursor;
    cursor += T2_BYTES;
    table->t3 = cursor;
    cursor += T2_BYTES;
    table->xor_tables = cursor;
    cursor += XOR_BYTES;
    table->xor_state = cursor;
    return 0;
}

static const uint8_t *t1_box(const fm_wb_table *table, int round, int box) {
    size_t index = (size_t) round * T1_BOXES + (size_t) box;
    return table->t1 + index * T1_ROWS * T1_OUT;
}

static const uint8_t *t2_box(const fm_wb_table *table, int round, int box) {
    size_t index = (size_t) round * T2_BOXES + (size_t) box;
    return table->t2 + index * T2_ROWS * T2_OUT;
}

static const uint8_t *t3_box(const fm_wb_table *table, int round, int box) {
    size_t index = (size_t) round * T2_BOXES + (size_t) box;
    return table->t3 + index * T2_ROWS * T2_OUT;
}

static uint32_t t2_lookup(const uint8_t *box, uint8_t value) {
    return read_u32(box + (size_t) value * T2_OUT);
}

static const uint8_t *xor_cascade(const fm_wb_table *table, int cascade) {
    return table->xor_tables + (size_t) cascade * XOR_BOXES * XOR_ROWS * 256;
}

static const uint8_t *xor_state_cascade(const fm_wb_table *table, int cascade) {
    return table->xor_state
           + (size_t) cascade * XOR_STATE_BOXES * XOR_STATE_ROWS * 256;
}

static uint32_t xor32(const uint8_t *box, uint32_t a, uint32_t b) {
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t index = (((a >> (i * 4)) & 0xF) << 4) | ((b >> (i * 4)) & 0xF);
        result |= (uint32_t) box[(size_t) i * 256 + index] << (i * 4);
    }
    return result;
}

static void xor3(const uint8_t *cascade, uint32_t a, uint32_t b,
                 uint32_t c, uint32_t d, uint32_t *out) {
    const uint8_t *left = cascade;
    const uint8_t *right = cascade + XOR_ROWS * 256;
    const uint8_t *top = cascade + 2 * XOR_ROWS * 256;
    *out = xor32(top, xor32(left, a, b), xor32(right, c, d));
}

static void xor_state_into(const uint8_t *box, uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) {
        uint8_t low = box[(size_t) (2 * i) * 256
                          + (((a[i] & 0xF) << 4) | (b[i] & 0xF))];
        uint8_t high = box[(size_t) (2 * i + 1) * 256
                           + ((((a[i] >> 4) & 0xF) << 4) | ((b[i] >> 4) & 0xF))];
        a[i] = (uint8_t) (low | (high << 4));
    }
}

static void cascade_state(const uint8_t *cascade, uint8_t states[16][16]) {
    int offset = 0;
    for (int stage = 0; stage < 4; stage++) {
        int iterations = 8 >> stage;
        int step = 1 << stage;
        for (int i = 0; i < iterations; i++) {
            const uint8_t *box = cascade
                                 + (size_t) (offset + i) * XOR_STATE_ROWS * 256;
            xor_state_into(box, states[2 * i * step], states[2 * i * step + step]);
        }
        offset += iterations;
    }
}

static void wb_crypt(const fm_wb_table *table, uint8_t state[16]) {
    uint8_t ares[16][16];
    uint32_t ires[16];

    for (int i = 0; i < 16; i++) {
        const uint8_t *box = t1_box(table, 0, i);
        memcpy(ares[i], box + (size_t) state[i] * T1_OUT, T1_OUT);
    }
    cascade_state(xor_state_cascade(table, 0), ares);
    memcpy(state, ares[0], 16);

    for (int round = 0; round < T2_ROUNDS - 1; round++) {
        for (int i = 0; i < 16; i++) {
            ires[i] = t2_lookup(t2_box(table, round, i),
                                state[SHIFT_ROWS[i]]);
        }
        for (int i = 0; i < 4; i++) {
            uint32_t column;
            xor3(xor_cascade(table, round * 8 + 2 * i),
                 ires[i], ires[4 + i], ires[8 + i], ires[12 + i], &column);
            ires[i] = column;
            uint8_t bytes[4] = {
                (uint8_t) (column & 0xFF),
                (uint8_t) ((column >> 8) & 0xFF),
                (uint8_t) ((column >> 16) & 0xFF),
                (uint8_t) ((column >> 24) & 0xFF),
            };
            ires[12 + i] = t2_lookup(t3_box(table, round, 12 + i), bytes[3]);
            ires[8 + i] = t2_lookup(t3_box(table, round, 8 + i), bytes[2]);
            ires[4 + i] = t2_lookup(t3_box(table, round, 4 + i), bytes[1]);
            ires[i] = t2_lookup(t3_box(table, round, i), bytes[0]);
            xor3(xor_cascade(table, round * 8 + 2 * i + 1),
                 ires[i], ires[4 + i], ires[8 + i], ires[12 + i], &column);
            state[i] = (uint8_t) (column & 0xFF);
            state[i + 4] = (uint8_t) ((column >> 8) & 0xFF);
            state[i + 8] = (uint8_t) ((column >> 16) & 0xFF);
            state[i + 12] = (uint8_t) ((column >> 24) & 0xFF);
        }
    }

    for (int i = 0; i < 16; i++) {
        const uint8_t *box = t1_box(table, 1, i);
        memcpy(ares[i], box + (size_t) state[SHIFT_ROWS[i]] * T1_OUT, T1_OUT);
    }
    cascade_state(xor_state_cascade(table, 1), ares);
    memcpy(state, ares[0], 16);
}

static void transpose(uint8_t state[16]) {
    uint8_t copy[16];
    memcpy(copy, state, 16);
    for (int i = 0; i < 16; i++) {
        state[i] = copy[(i % 4) * 4 + i / 4];
    }
}

static void keystream(const fm_wb_table *table, const uint8_t nonce[12],
                      uint8_t *out, size_t length) {
    uint8_t block[16];
    memset(block, 0, sizeof(block));
    memcpy(block, nonce, 12);
    for (size_t offset = 0, counter = 0; offset < length; offset += 16, counter++) {
        block[12] = (uint8_t) (counter >> 24);
        block[13] = (uint8_t) (counter >> 16);
        block[14] = (uint8_t) (counter >> 8);
        block[15] = (uint8_t) counter;
        uint8_t state[16];
        memcpy(state, block, 16);
        transpose(state);
        wb_crypt(table, state);
        size_t take = length - offset < 16 ? length - offset : 16;
        memcpy(out + offset, state, take);
    }
}

int fm_wb_unwrap(const fm_wb_table *table, const uint8_t *blob, size_t len,
                 uint8_t out[FM_WB_KEY_SIZE]) {
    if (table == NULL || blob == NULL || len != 4 + FM_WB_NONCE_SIZE + FM_WB_KEY_SIZE) {
        return -1;
    }
    if (blob[0] != 'W' || blob[1] != 'B' || blob[2] != 'K' || blob[3] != '1') {
        return -1;
    }
    uint8_t stream[FM_WB_KEY_SIZE];
    keystream(table, blob + 4, stream, sizeof(stream));
    for (int i = 0; i < FM_WB_KEY_SIZE; i++) {
        out[i] = blob[4 + FM_WB_NONCE_SIZE + i] ^ stream[i];
    }
    memset(stream, 0, sizeof(stream));
    return 0;
}
