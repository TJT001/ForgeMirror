#ifndef FORGEMIRROR_ABI_H
#define FORGEMIRROR_ABI_H

#include <stdint.h>

#define FM_ABI_VERSION 1u

#if defined(__GNUC__) || defined(__clang__)
#define FM_API __attribute__((visibility("default")))
#else
#define FM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 所有跨边界结构体必须以该头开始；调用方填入 struct_size 与 abi_version。 */
typedef struct fm_struct_header {
    uint32_t struct_size;
    uint32_t abi_version;
} fm_struct_header;

typedef int32_t fm_status;

#define FM_OK 0
#define FM_INVALID_ARGUMENT 1
#define FM_ABI_MISMATCH 2
#define FM_OUT_OF_MEMORY 3
#define FM_NOT_INITIALIZED 4
#define FM_INTEGRITY 5
#define FM_IO 6
#define FM_NO_KEY 7
#define FM_RECOVERY_REQUIRED 8
#define FM_UNSUPPORTED 9
#define FM_INTERNAL 255

typedef struct fm_core fm_core;
typedef struct fm_key_provider fm_key_provider;

FM_API uint32_t fm_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif
