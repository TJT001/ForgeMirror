#include "fm_vault.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "fm_aes.h"
#include "fm_sha256.h"
#include "fm_whitebox.h"

#define HEADER_SIZE 128
#define ENTRY_SIZE 72
#define CHUNK_SIZE 65536
#define TAG_SIZE 16
#define MAX_FILES 64
#define MAX_CHUNKS 32768
#define MAX_FILE (1ull << 30)
#define MAX_TOTAL (2ull << 30)

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_key[32];
static int g_ready;

static const char TOC_LABEL[] = "FM/fdx2/toc/v1";
static const char CHUNK_LABEL[] = "FM/fdx2/chunk/v1";

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    return (uint64_t) rd32(p) | ((uint64_t) rd32(p + 4) << 32);
}

static void wr32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t) value;
    p[1] = (uint8_t) (value >> 8);
    p[2] = (uint8_t) (value >> 16);
    p[3] = (uint8_t) (value >> 24);
}

static void hkdf(const uint8_t ikm[32], const uint8_t salt[16],
                 const char *label, uint8_t out[32]) {
    uint8_t prk[32];
    fm_hmac_sha256(salt, 16, ikm, 32, prk);
    uint8_t data[64];
    size_t length = strlen(label);
    memcpy(data, label, length);
    data[length] = 0x01;
    fm_hmac_sha256(prk, 32, data, length + 1, out);
    memset(prk, 0, sizeof(prk));
    memset(data, 0, sizeof(data));
}

static int install_key(const uint8_t key[32]) {
    pthread_mutex_lock(&g_lock);
    memcpy(g_key, key, 32);
    g_ready = 1;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

int fm_vault_install(const uint8_t *blob, size_t blob_len,
                     const uint8_t *table, size_t table_len) {
    if (blob == NULL || table == NULL) {
        return -1;
    }
    fm_wb_table parsed;
    if (fm_wb_parse(table, table_len, &parsed) != 0) {
        return -1;
    }
    uint8_t key[32];
    if (fm_wb_unwrap(&parsed, blob, blob_len, key) != 0) {
        return -1;
    }
    install_key(key);
    memset(key, 0, sizeof(key));
    return 0;
}

int fm_vault_install_raw(const uint8_t *key, size_t key_len) {
    if (key == NULL || key_len != 32) {
        return -1;
    }
    install_key(key);
    return 0;
}

int fm_vault_derive(int id, const uint8_t build_id[16], uint8_t out[32]) {
    const char *label;
    switch (id) {
        case FM_DERIVE_POLICY:
            label = "FM/policy/v1";
            break;
        case FM_DERIVE_FILE:
            label = "FM/files/v1";
            break;
        case FM_DERIVE_NATIVE:
            label = "FM/native/v1";
            break;
        case FM_DERIVE_RULES:
            label = "FM/rules/v1";
            break;
        case FM_DERIVE_CORE:
            label = "FM/core/v1";
            break;
        default:
            return -1;
    }
    if (build_id == NULL || out == NULL) {
        return -1;
    }
    pthread_mutex_lock(&g_lock);
    if (!g_ready) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    hkdf(g_key, build_id, label, out);
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void fm_vault_clear(void) {
    pthread_mutex_lock(&g_lock);
    memset(g_key, 0, sizeof(g_key));
    g_ready = 0;
    pthread_mutex_unlock(&g_lock);
}

static void chunk_aad(uint8_t aad[40], const uint8_t build_id[16],
                      uint32_t file_index, uint32_t chunk_index,
                      uint32_t plaintext_len) {
    memcpy(aad, "FDX2", 4);
    aad[4] = 2;
    aad[5] = 0;
    aad[6] = 1;
    aad[7] = 1;
    memcpy(aad + 8, build_id, 16);
    wr32(aad + 24, file_index);
    wr32(aad + 28, chunk_index);
    wr32(aad + 32, plaintext_len);
    wr32(aad + 36, 0);
}

int fm_container_open(const uint8_t *container, size_t len,
                      fm_file **files, int *count) {
    if (container == NULL || files == NULL || count == NULL) {
        return -1;
    }
    if (len < HEADER_SIZE || memcmp(container, "FDX2", 4) != 0) {
        return -1;
    }
    if (rd16(container + 4) != 2 || rd16(container + 6) != HEADER_SIZE
        || rd32(container + 8) != 0 || container[12] != 1 || container[13] != 1
        || rd16(container + 14) != 0 || rd32(container + 60) != 0
        || rd32(container + 76) != 0) {
        return -1;
    }
    uint32_t file_count = rd32(container + 32);
    uint32_t chunk_size = rd32(container + 36);
    uint32_t total_chunks = rd32(container + 72);
    uint64_t total_plain = rd64(container + 64);
    uint64_t toc_offset = rd64(container + 80);
    uint64_t toc_size = rd64(container + 88);
    if (file_count < 1 || file_count > MAX_FILES || chunk_size != CHUNK_SIZE
        || total_chunks > MAX_CHUNKS || total_plain > MAX_TOTAL) {
        return -1;
    }
    if (toc_offset < HEADER_SIZE || toc_offset > len
        || toc_size != TAG_SIZE + (uint64_t) ENTRY_SIZE * file_count
        || toc_offset + toc_size != len) {
        return -1;
    }

    const uint8_t *build_id = container + 16;
    const uint8_t *nonce_prefix = container + 40;
    const uint8_t *toc_nonce = container + 48;

    uint8_t toc_key[32];
    uint8_t chunk_key[32];
    pthread_mutex_lock(&g_lock);
    if (!g_ready) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    hkdf(g_key, build_id, TOC_LABEL, toc_key);
    hkdf(g_key, build_id, CHUNK_LABEL, chunk_key);
    pthread_mutex_unlock(&g_lock);

    size_t toc_plain_size = (size_t) ENTRY_SIZE * file_count;
    uint8_t *toc = (uint8_t *) malloc(toc_plain_size);
    if (toc == NULL) {
        memset(toc_key, 0, sizeof(toc_key));
        memset(chunk_key, 0, sizeof(chunk_key));
        return -1;
    }
    int status = fm_gcm_decrypt(toc_key, toc_nonce, container, HEADER_SIZE,
                                container + toc_offset,
                                (size_t) toc_size - TAG_SIZE,
                                container + toc_offset + toc_size - TAG_SIZE,
                                toc);
    memset(toc_key, 0, sizeof(toc_key));
    if (status != 0) {
        memset(chunk_key, 0, sizeof(chunk_key));
        free(toc);
        return -1;
    }

    fm_file *output = (fm_file *) calloc(file_count, sizeof(fm_file));
    if (output == NULL) {
        memset(chunk_key, 0, sizeof(chunk_key));
        free(toc);
        return -1;
    }

    uint64_t expected_offset = HEADER_SIZE;
    uint32_t expected_chunks = 0;
    uint64_t expected_plain = 0;
    for (uint32_t index = 0; index < file_count; index++) {
        const uint8_t *entry = toc + (size_t) index * ENTRY_SIZE;
        uint32_t file_index = rd32(entry);
        uint32_t file_flags = rd32(entry + 4);
        uint64_t size = rd64(entry + 16);
        uint32_t entry_chunk_size = rd32(entry + 24);
        uint32_t chunk_count = rd32(entry + 28);
        uint64_t data_offset = rd64(entry + 32);
        if (file_index != index || file_flags != 0 || entry_chunk_size != CHUNK_SIZE
            || size > MAX_FILE
            || chunk_count != (uint32_t) ((size + CHUNK_SIZE - 1) / CHUNK_SIZE)
            || data_offset != expected_offset || data_offset > toc_offset) {
            status = -1;
            break;
        }
        uint64_t remaining = size;
        for (uint32_t i = 0; i < chunk_count; i++) {
            uint64_t span = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
            expected_offset += span + TAG_SIZE;
            remaining -= span;
        }
        if (expected_offset > toc_offset) {
            status = -1;
            break;
        }
        expected_chunks += chunk_count;
        expected_plain += size;
        if (expected_chunks > MAX_CHUNKS || expected_plain > MAX_TOTAL) {
            status = -1;
            break;
        }
    }
    if (status != 0 || expected_offset != toc_offset
        || expected_chunks != total_chunks || expected_plain != total_plain) {
        memset(chunk_key, 0, sizeof(chunk_key));
        free(toc);
        free(output);
        return -1;
    }

    size_t cursor = HEADER_SIZE;
    uint32_t global_chunk = 0;
    for (uint32_t index = 0; index < file_count && status == 0; index++) {
        const uint8_t *entry = toc + (size_t) index * ENTRY_SIZE;
        uint64_t size = rd64(entry + 16);
        const uint8_t *digest = entry + 40;
        uint8_t *plain = (uint8_t *) malloc(size == 0 ? 1 : (size_t) size);
        if (plain == NULL) {
            status = -1;
            break;
        }
        uint64_t remaining = size;
        size_t written = 0;
        while (remaining > 0) {
            uint32_t length = (uint32_t) (remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE);
            size_t ciphertext_len = (size_t) length + TAG_SIZE;
            if (cursor + ciphertext_len > len) {
                status = -1;
                break;
            }
            uint8_t nonce[12];
            memcpy(nonce, nonce_prefix, 8);
            nonce[8] = (uint8_t) (global_chunk >> 24);
            nonce[9] = (uint8_t) (global_chunk >> 16);
            nonce[10] = (uint8_t) (global_chunk >> 8);
            nonce[11] = (uint8_t) global_chunk;
            uint8_t aad[40];
            chunk_aad(aad, build_id, index, global_chunk, length);
            status = fm_gcm_decrypt(chunk_key, nonce, aad, sizeof(aad),
                                    container + cursor, length,
                                    container + cursor + length,
                                    plain + written);
            if (status != 0) {
                break;
            }
            written += length;
            remaining -= length;
            cursor += ciphertext_len;
            global_chunk++;
        }
        if (status != 0) {
            free(plain);
            break;
        }
        uint8_t actual[32];
        fm_sha256(plain, (size_t) size, actual);
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) {
            diff |= (uint8_t) (actual[i] ^ digest[i]);
        }
        if (diff != 0) {
            free(plain);
            status = -1;
            break;
        }
        output[index].data = plain;
        output[index].size = (size_t) size;
    }
    memset(chunk_key, 0, sizeof(chunk_key));
    free(toc);
    if (status != 0 || cursor != toc_offset) {
        fm_container_free(output, (int) file_count);
        return -1;
    }
    *files = output;
    *count = (int) file_count;
    return 0;
}

void fm_container_free(fm_file *files, int count) {
    if (files == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        if (files[i].data != NULL) {
            memset(files[i].data, 0, files[i].size);
            free(files[i].data);
        }
    }
    free(files);
}

int fm_vault_decrypt_package(int id, const uint8_t build_id[16],
                             const uint8_t *pkg, size_t len,
                             int header_size, int nonce_offset, int sig_size,
                             uint8_t **out, size_t *out_len) {
    if (pkg == NULL || out == NULL || out_len == NULL
        || header_size < 16 || (size_t) header_size >= len
        || nonce_offset < 0 || (size_t) nonce_offset + 12 > (size_t) header_size
        || sig_size < 0 || (size_t) sig_size + TAG_SIZE >= len - (size_t) header_size) {
        return -1;
    }
    uint8_t key[32];
    if (fm_vault_derive(id, build_id, key) != 0) {
        return -1;
    }
    size_t end = len - (size_t) sig_size - TAG_SIZE;
    size_t ciphertext_len = end - (size_t) header_size;
    uint8_t *plain = (uint8_t *) malloc(ciphertext_len);
    if (plain == NULL) {
        memset(key, 0, sizeof(key));
        return -1;
    }
    int status = fm_gcm_decrypt(key, pkg + nonce_offset, pkg, (size_t) header_size,
                                pkg + header_size, ciphertext_len,
                                pkg + end, plain);
    memset(key, 0, sizeof(key));
    if (status != 0) {
        free(plain);
        return -1;
    }
    *out = plain;
    *out_len = ciphertext_len;
    return 0;
}

void fm_free_bytes(uint8_t *buffer) {
    free(buffer);
}
