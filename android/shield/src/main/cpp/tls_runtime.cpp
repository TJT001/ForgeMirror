#include "tls_runtime.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <mutex>

namespace {

constexpr int kMaxModules = 64;
constexpr uintptr_t kModuleBase = 0x40000000u;

struct Module {
    size_t size = 0;
    size_t align = 16;
    unsigned char *init = nullptr;
    size_t initSize = 0;
};

Module gModules[kMaxModules];
int gModuleCount = 0;
std::mutex gLock;
pthread_key_t gKey;
pthread_once_t gKeyOnce = PTHREAD_ONCE_INIT;

void destroyBlocks(void *value) {
    auto *blocks = static_cast<unsigned char **>(value);
    if (blocks == nullptr) {
        return;
    }
    for (int index = 0; index < kMaxModules; index++) {
        free(blocks[index]);
    }
    free(blocks);
}

void createKey() {
    pthread_key_create(&gKey, destroyBlocks);
}

unsigned char **threadBlocks() {
    pthread_once(&gKeyOnce, createKey);
    auto *blocks = static_cast<unsigned char **>(pthread_getspecific(gKey));
    if (blocks == nullptr) {
        blocks = static_cast<unsigned char **>(
                calloc(kMaxModules, sizeof(unsigned char *)));
        if (blocks != nullptr) {
            pthread_setspecific(gKey, blocks);
        }
    }
    return blocks;
}

}  // namespace

extern "C" __attribute__((visibility("default")))
uintptr_t fm_tls_register(size_t size, size_t align, const void *init,
                          size_t init_size) {
    if (size == 0 || align == 0 || (align & (align - 1)) != 0) {
        return 0;
    }
    unsigned char *copy = nullptr;
    if (init_size > 0) {
        copy = static_cast<unsigned char *>(malloc(init_size));
        if (copy == nullptr) {
            return 0;
        }
        memcpy(copy, init, init_size);
    }
    std::lock_guard<std::mutex> guard(gLock);
    if (gModuleCount >= kMaxModules) {
        free(copy);
        return 0;
    }
    Module &module = gModules[gModuleCount];
    module.size = size;
    module.align = align < sizeof(void *) ? sizeof(void *) : align;
    module.init = copy;
    module.initSize = init_size > size ? size : init_size;
    return kModuleBase + static_cast<uintptr_t>(gModuleCount++);
}

extern "C" __attribute__((visibility("default")))
void *fm_tls_get_addr_entry(void *index) {
    return fm_tls_get_addr(index);
}

extern "C" __attribute__((visibility("default")))
void *fm_tls_get_addr(void *index) {
    if (index == nullptr) {
        return nullptr;
    }
    auto *entry = static_cast<FmTlsIndex *>(index);
    if (entry->module < kModuleBase) {
        return nullptr;
    }
    uintptr_t slot = entry->module - kModuleBase;
    std::lock_guard<std::mutex> guard(gLock);
    if (slot >= static_cast<uintptr_t>(gModuleCount)) {
        return nullptr;
    }
    Module &module = gModules[slot];
    unsigned char **blocks = threadBlocks();
    if (blocks == nullptr) {
        return nullptr;
    }
    if (blocks[slot] == nullptr) {
        void *memory = nullptr;
        if (posix_memalign(&memory, module.align, module.size) != 0) {
            return nullptr;
        }
        memset(memory, 0, module.size);
        if (module.init != nullptr && module.initSize > 0) {
            memcpy(memory, module.init, module.initSize);
        }
        blocks[slot] = static_cast<unsigned char *>(memory);
    }
    if (entry->offset > module.size) {
        return nullptr;
    }
    return blocks[slot] + entry->offset;
}

#if defined(__aarch64__)
extern "C" __attribute__((visibility("default")))
uintptr_t fm_tlsdesc_resolve(void *descriptor) {
    auto *desc = static_cast<FmTlsDesc *>(descriptor);
    if (desc == nullptr || desc->argument == nullptr) {
        return 0;
    }
    void *address = fm_tls_get_addr(desc->argument);
    uintptr_t threadPointer = reinterpret_cast<uintptr_t>(
            __builtin_thread_pointer());
    return reinterpret_cast<uintptr_t>(address) - threadPointer;
}
#endif
