#include "forgemirror/boot.h"
#include "forgemirror/core.h"

_Static_assert(sizeof(uint32_t) == 4, "ABI requires 32-bit fields");

void fm_abi_compile_check(void) {
    fm_core_config config = {0};
    config.header.struct_size = sizeof(config);
    config.header.abi_version = FM_ABI_VERSION;

    fm_boot_ctx ctx = {0};
    ctx.header.struct_size = sizeof(ctx);
    ctx.header.abi_version = FM_ABI_VERSION;

    if (fm_boot_verify(&ctx) == FM_OK) {
        fm_core *core = 0;
        if (fm_core_create(&config, &core) == FM_OK) {
            fm_core_destroy(core);
        }
    }
}
