#ifndef FM_VAULT_H
#define FM_VAULT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FM_DERIVE_POLICY = 1,
    FM_DERIVE_FILE = 2,
    FM_DERIVE_NATIVE = 3,
    FM_DERIVE_RULES = 4,
    FM_DERIVE_CORE = 5,
} fm_derive_id;

typedef struct {
    uint8_t *data;
    size_t size;
} fm_file;

/* Installs a wrapped WBK1 blob (white-box) or a raw 32-byte key. */
int fm_vault_install(const uint8_t *blob, size_t blob_len,
                     const uint8_t *table, size_t table_len);
int fm_vault_install_raw(const uint8_t *key, size_t key_len);
int fm_vault_derive(int id, const uint8_t build_id[16], uint8_t out[32]);
void fm_vault_clear(void);

/* Decrypts an FDX2 container; files must be released with fm_container_free. */
int fm_container_open(const uint8_t *container, size_t len,
                      fm_file **files, int *count);
void fm_container_free(fm_file *files, int count);

/* Decrypts a signed package envelope (SPK1/PKR1/FMC1 layout) with the key
 * derived for the given id. The caller frees *out with fm_free_bytes. */
int fm_vault_decrypt_package(int id, const uint8_t build_id[16],
                             const uint8_t *pkg, size_t len,
                             int header_size, int nonce_offset, int sig_size,
                             uint8_t **out, size_t *out_len);
void fm_free_bytes(uint8_t *buffer);

#ifdef __cplusplus
}
#endif

#endif
