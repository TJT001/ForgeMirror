#include <jni.h>

#include <cstddef>

#include "forgemirror/boot.h"
#include "forgemirror/core.h"

namespace {

fm_status validate_header(const fm_struct_header *header, size_t expected_size) {
    if (header == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    if (header->abi_version != FM_ABI_VERSION) {
        return FM_ABI_MISMATCH;
    }
    if (header->struct_size < expected_size) {
        return FM_INVALID_ARGUMENT;
    }
    return FM_OK;
}

}  // namespace

extern "C" uint32_t fm_boot_abi_version(void) {
    return FM_ABI_VERSION;
}

extern "C" fm_status fm_boot_verify(const fm_boot_ctx *ctx) {
    if (ctx == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    const fm_status status = validate_header(&ctx->header, sizeof(fm_boot_ctx));
    if (status != FM_OK) {
        return status;
    }
    return FM_NOT_INITIALIZED;
}

extern "C" fm_status fm_boot(const fm_boot_ctx *ctx, fm_core **out) {
    if (out == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    *out = nullptr;
    return fm_boot_verify(ctx);
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_abiVersion(JNIEnv *, jclass) {
    return static_cast<jint>(fm_core_abi_version());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_describe(JNIEnv *env, jclass) {
    fm_core_config config{};
    config.header.struct_size = sizeof(config);
    config.header.abi_version = FM_ABI_VERSION;

    fm_core *core = nullptr;
    fm_status status = fm_core_create(&config, &core);
    if (status == FM_OK) {
        status = fm_core_init(core, &config);
    }
    fm_core_destroy(core);

    return env->NewStringUTF(status == FM_OK
                                     ? "ForgeMirror: Core ABI v1 ready (P0 probe)"
                                     : "ForgeMirror: Core initialization failed");
}
