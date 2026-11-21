#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

struct FmTlsIndex {
    uintptr_t module;
    uintptr_t offset;
};

struct FmTlsDesc {
    void *resolver;
    void *argument;
};

uintptr_t fm_tls_register(size_t size, size_t align, const void *init,
                          size_t init_size);
void *fm_tls_get_addr(void *index);

void *fm_tls_get_addr_entry(void *index);
#if defined(__aarch64__)
uintptr_t fm_tlsdesc_resolve(void *descriptor);
#endif

}
