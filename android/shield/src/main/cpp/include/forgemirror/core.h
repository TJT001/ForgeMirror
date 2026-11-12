#ifndef FORGEMIRROR_CORE_H
#define FORGEMIRROR_CORE_H

#include "abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fm_core_config {
    fm_struct_header header;
    fm_key_provider *key_provider;
    const char *data_dir;
    uint32_t flags;
    uint32_t reserved;
} fm_core_config;

FM_API uint32_t fm_core_abi_version(void);

/* 分配并初始化；失败时 *out 为 NULL，成功句柄由 fm_core_destroy 释放。 */
FM_API fm_status fm_core_create(const fm_core_config *config, fm_core **out);
FM_API fm_status fm_core_init(fm_core *core, const fm_core_config *config);

/* classloader_out 为 Java ClassLoader 的全局引用，所有权移交调用方。 */
FM_API fm_status fm_core_load_dex(fm_core *core, const char *container_path,
                                  void **classloader_out);

/* scope: 0=启动关键产物全量，1=抽样。 */
FM_API fm_status fm_core_verify(fm_core *core, uint32_t scope);

FM_API fm_status fm_core_policy_apply(fm_core *core, const char *path);
FM_API fm_status fm_core_report(fm_core *core, const char *event_json);
FM_API void fm_core_destroy(fm_core *core);

#ifdef __cplusplus
}
#endif

#endif
