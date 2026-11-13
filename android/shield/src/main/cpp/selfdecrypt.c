/* DT_INIT LZSS self-decrypt bootstrap. The post-build step compresses and
 * encrypts .text, appends the payload, and fills fm_meta. */
#include <stddef.h>
#include <stdint.h>
#include <android/log.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#define FM_MAGIC 0x464d53444c5a3031ULL

struct fm_meta {
    uint64_t magic;
    uint64_t target_vaddr;
    uint64_t target_size;
    uint64_t payload_vaddr;
    uint64_t payload_size;
    uint64_t dynamic_vaddr;
    uint8_t key[32];
} __attribute__((packed));

__attribute__((section(".fm_meta"), used, aligned(8)))
struct fm_meta fm_meta = {
        .magic = FM_MAGIC,
        .target_vaddr = 0,
        .target_size = 0,
        .payload_vaddr = 0,
        .payload_size = 0,
        .dynamic_vaddr = 0,
        .key = {0},
};

extern char _DYNAMIC[];

__attribute__((used, noinline, section(".fm_selfdecrypt")))
static uint8_t fm_read(const uint8_t *src, size_t *position, const uint8_t *key) {
    uint8_t value = src[*position] ^ key[*position & 31];
    (*position)++;
    return value;
}

__attribute__((used, noinline, section(".fm_selfdecrypt")))
static int fm_lzss(const uint8_t *src, size_t src_len, uint8_t *dst,
                   size_t dst_len, const uint8_t *key) {
    size_t in = 0;
    size_t out = 0;
    uint8_t flags = 0;
    int bit = 8;
    while (out < dst_len) {
        if (bit == 8) {
            if (in >= src_len) {
                return 0;
            }
            flags = fm_read(src, &in, key);
            bit = 0;
        }
        if ((flags & (1u << bit)) != 0) {
            if (in >= src_len) {
                return 0;
            }
            dst[out++] = fm_read(src, &in, key);
        } else {
            if (in + 1 >= src_len) {
                return 0;
            }
            uint8_t low = fm_read(src, &in, key);
            uint8_t high = fm_read(src, &in, key);
            size_t offset = (size_t) low | ((size_t) (high & 0xF0) << 4);
            size_t length = (size_t) (high & 0x0F) + 3;
            if (offset + 1 > out) {
                return 0;
            }
            for (size_t index = 0; index < length && out < dst_len; index++) {
                dst[out] = dst[out - offset - 1];
                out++;
            }
        }
        bit++;
    }
    return 1;
}

__attribute__((used, noinline, section(".fm_selfdecrypt")))
static void fm_clear_cache(void *start, void *end) {
#if defined(__aarch64__)
    uintptr_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uintptr_t line = (uintptr_t) 4 << ((ctr >> 16) & 0xf);
    uintptr_t begin = (uintptr_t) start & ~(line - 1);
    for (uintptr_t address = begin; address < (uintptr_t) end; address += line) {
        __asm__ volatile("dc cvau, %0" ::"r"(address));
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t address = begin; address < (uintptr_t) end; address += line) {
        __asm__ volatile("ic ivau, %0" ::"r"(address));
    }
    __asm__ volatile("dsb ish\nisb" ::: "memory");
#elif defined(__arm__)
    register long r0 __asm__("r0") = (long) start;
    register long r1 __asm__("r1") = (long) end;
    register long r2 __asm__("r2") = 0;
    long number = 0x0f0002;  /* __ARM_NR_cacheflush */
    __asm__ volatile("mov r6, r7\n\tmov r7, %[nr]\n\tsvc #0\n\tmov r7, r6"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), [nr] "r"(number)
                     : "r6", "memory");
#else
    (void) start;
    (void) end;
#endif
}

__attribute__((used, noinline, section(".fm_selfdecrypt")))
void fm_selfdecrypt_init(void) {
    if (fm_meta.magic != FM_MAGIC || fm_meta.target_size == 0 ||
        fm_meta.payload_size == 0) {
        return;
    }
    uintptr_t base = (uintptr_t) _DYNAMIC - (uintptr_t) fm_meta.dynamic_vaddr;
    uint8_t *target = (uint8_t *) (base + fm_meta.target_vaddr);
    const uint8_t *payload = (const uint8_t *) (base + fm_meta.payload_vaddr);
    uintptr_t page = (uintptr_t) sysconf(_SC_PAGESIZE);
    if (page == 0) {
        page = 4096;
    }
    uintptr_t start = (uintptr_t) target & ~(page - 1);
    uintptr_t end = ((uintptr_t) target + fm_meta.target_size + page - 1) &
                    ~(page - 1);
    __android_log_print(ANDROID_LOG_INFO, "FMDecrypt",
                        "init base=%p target=%p size=%llu payload=%p len=%llu",
                        (void *) base, (void *) target,
                        (unsigned long long) fm_meta.target_size,
                        (void *) payload,
                        (unsigned long long) fm_meta.payload_size);
    int protect = mprotect((void *) start, end - start,
                           PROT_READ | PROT_WRITE | PROT_EXEC);
    if (protect != 0) {
        __android_log_print(ANDROID_LOG_WARN, "FMDecrypt",
                            "mprotect failed errno=%d", errno);
        return;
    }
    int ok = fm_lzss(payload, fm_meta.payload_size, target,
                     fm_meta.target_size, fm_meta.key);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_WARN, "FMDecrypt",
                        "lzss ok=%d", ok);
    if (!ok) {
        return;
    }
    uint64_t hash = 1469598103934665603ULL;
    for (uint64_t index = 0; index < fm_meta.target_size; index++) {
        hash = (hash ^ target[index]) * 1099511628211ULL;
    }
    __android_log_print(ANDROID_LOG_INFO, "FMDecrypt", "hash=%016llx",
                        (unsigned long long) hash);
    fm_clear_cache(target, target + fm_meta.target_size);
    mprotect((void *) start, end - start, PROT_READ | PROT_EXEC);
    __android_log_print(ANDROID_LOG_INFO, "FMDecrypt", "stub done");
}
