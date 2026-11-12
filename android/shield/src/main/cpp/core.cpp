#include "forgemirror/core.h"

#include <new>

struct fm_core {
    uint32_t abi_version;
    uint32_t flags;
};

namespace {

fm_status validate_config(const fm_core_config *config) {
    if (config == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    if (config->header.abi_version != FM_ABI_VERSION) {
        return FM_ABI_MISMATCH;
    }
    if (config->header.struct_size < sizeof(fm_core_config)) {
        return FM_INVALID_ARGUMENT;
    }
    return FM_OK;
}

}  // namespace

extern "C" uint32_t fm_abi_version(void) {
    return FM_ABI_VERSION;
}

extern "C" uint32_t fm_core_abi_version(void) {
    return FM_ABI_VERSION;
}

extern "C" fm_status fm_core_create(const fm_core_config *config, fm_core **out) {
    if (out == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    *out = nullptr;
    const fm_status status = validate_config(config);
    if (status != FM_OK) {
        return status;
    }
    fm_core *core = new (std::nothrow) fm_core{config->header.abi_version, config->flags};
    if (core == nullptr) {
        return FM_OUT_OF_MEMORY;
    }
    *out = core;
    return FM_OK;
}

extern "C" fm_status fm_core_init(fm_core *core, const fm_core_config *config) {
    if (core == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    const fm_status status = validate_config(config);
    if (status != FM_OK) {
        return status;
    }
    core->flags = config->flags;
    return FM_OK;
}

extern "C" fm_status fm_core_load_dex(fm_core *core, const char *container_path,
                                      void **classloader_out) {
    if (core == nullptr || container_path == nullptr || classloader_out == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    *classloader_out = nullptr;
    return FM_NOT_INITIALIZED;
}

extern "C" fm_status fm_core_verify(fm_core *core, uint32_t scope) {
    if (core == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    (void) scope;
    return FM_NOT_INITIALIZED;
}

extern "C" fm_status fm_core_policy_apply(fm_core *core, const char *path) {
    if (core == nullptr || path == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    return FM_NOT_INITIALIZED;
}

extern "C" fm_status fm_core_report(fm_core *core, const char *event_json) {
    if (core == nullptr || event_json == nullptr) {
        return FM_INVALID_ARGUMENT;
    }
    return FM_NOT_INITIALIZED;
}

extern "C" void fm_core_destroy(fm_core *core) {
    delete core;
}
