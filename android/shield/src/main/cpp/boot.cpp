#include <dlfcn.h>
#include <jni.h>

#include <cstddef>
#include <cstdint>

#include "forgemirror/boot.h"
#include "forgemirror/core.h"

namespace {

struct CoreApi {
    void *handle = nullptr;
    uint32_t (*abi_version)() = nullptr;
    fm_status (*create)(const fm_core_config *, fm_core **) = nullptr;
    fm_status (*init)(fm_core *, const fm_core_config *) = nullptr;
    void (*destroy)(fm_core *) = nullptr;
};

CoreApi load_core() {
    CoreApi api{};
    api.handle = dlopen("libshield_core.so", RTLD_NOW | RTLD_LOCAL);
    if (api.handle == nullptr) {
        return api;
    }
    api.abi_version = reinterpret_cast<uint32_t (*)()>(
            dlsym(api.handle, "fm_core_abi_version"));
    api.create = reinterpret_cast<fm_status (*)(const fm_core_config *, fm_core **)>(
            dlsym(api.handle, "fm_core_create"));
    api.init = reinterpret_cast<fm_status (*)(fm_core *, const fm_core_config *)>(
            dlsym(api.handle, "fm_core_init"));
    api.destroy = reinterpret_cast<void (*)(fm_core *)>(
            dlsym(api.handle, "fm_core_destroy"));
    if (api.abi_version == nullptr || api.create == nullptr || api.init == nullptr ||
        api.destroy == nullptr) {
        dlclose(api.handle);
        api = CoreApi{};
    }
    return api;
}

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
    // P1-B verifies the signed manifest in the Java stub; native verification
    // moves here when the approved crypto backend is integrated (P2).
    return validate_header(&ctx->header, sizeof(fm_boot_ctx));
}

extern "C" fm_status fm_boot(const fm_boot_ctx *ctx, fm_core **out) {
    if (out == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    *out = nullptr;

    const fm_status verified = fm_boot_verify(ctx);
    if (verified != FM_OK) {
        return verified;
    }

    CoreApi api = load_core();
    if (api.handle == nullptr) {
        return FM_RECOVERY_REQUIRED;
    }
    if (api.abi_version() != FM_ABI_VERSION) {
        dlclose(api.handle);
        return FM_ABI_MISMATCH;
    }

    fm_core_config config{};
    config.header.struct_size = sizeof(config);
    config.header.abi_version = FM_ABI_VERSION;

    fm_core *core = nullptr;
    fm_status status = api.create(&config, &core);
    if (status == FM_OK) {
        status = api.init(core, &config);
    }
    api.destroy(core);
    // The handle stays mapped for the process lifetime; later stages resolve
    // core_load_dex/verify through the same bounded API.
    return status;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_nativeBootstrap(JNIEnv *, jclass) {
    fm_boot_ctx ctx{};
    ctx.header.struct_size = sizeof(ctx);
    ctx.header.abi_version = FM_ABI_VERSION;
    fm_core *core = nullptr;
    return static_cast<jint>(fm_boot(&ctx, &core));
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_abiVersion(JNIEnv *, jclass) {
    return static_cast<jint>(fm_boot_abi_version());
}

extern "C" JNIEXPORT jstring JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_describe(JNIEnv *env, jclass) {
    fm_boot_ctx ctx{};
    ctx.header.struct_size = sizeof(ctx);
    ctx.header.abi_version = FM_ABI_VERSION;
    fm_core *core = nullptr;
    const fm_status status = fm_boot(&ctx, &core);
    return env->NewStringUTF(status == FM_OK
                                     ? "ForgeMirror: Core ABI v1 ready (P1-B boot)"
                                     : "ForgeMirror: Core initialization failed");
}
