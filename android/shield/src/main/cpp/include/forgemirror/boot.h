#ifndef FORGEMIRROR_BOOT_H
#define FORGEMIRROR_BOOT_H

#include "abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fm_boot_ctx {
    fm_struct_header header;
    const char *app_id;
    const char *version;
    const char *cert_sha256;
    uint32_t profile;
    uint32_t flags;
} fm_boot_ctx;

FM_API uint32_t fm_boot_abi_version(void);

/* 只校验清单与 Core 完整性，不加载。 */
FM_API fm_status fm_boot_verify(const fm_boot_ctx *ctx);

/* 校验成功后初始化 Core；失败时 *out 必须为 NULL。 */
FM_API fm_status fm_boot(const fm_boot_ctx *ctx, fm_core **out);

#ifdef __cplusplus
}
#endif

#endif
