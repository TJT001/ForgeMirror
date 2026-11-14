#include "forgemirror/elf_loader.h"

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace forgemirror::elf {

struct SegmentInfo {
    uintptr_t address;
    size_t memorySize;
    int prot;
};

struct Image {
    void *base = nullptr;
    size_t mappedSize = 0;
    std::string name;
    const ElfW(Sym) *symbols = nullptr;
    size_t symbolCount = 0;
    const char *strings = nullptr;
    std::vector<SegmentInfo> segments;
    uintptr_t relroAddress = 0;
    size_t relroSize = 0;
};

namespace {

constexpr const char *kTag = "FMElf";

#if defined(__LP64__)
#define FM_R_SYM ELF64_R_SYM
#define FM_R_TYPE ELF64_R_TYPE
#else
#define FM_R_SYM ELF32_R_SYM
#define FM_R_TYPE ELF32_R_TYPE
#endif

std::mutex gImagesLock;
std::vector<Image *> gImages;

size_t pageSize() {
    static size_t value = [] {
        long result = sysconf(_SC_PAGESIZE);
        return result > 0 ? static_cast<size_t>(result) : 4096u;
    }();
    return value;
}

uintptr_t alignDown(uintptr_t value) {
    return value & ~(static_cast<uintptr_t>(pageSize()) - 1);
}

uintptr_t alignUp(uintptr_t value) {
    return (value + pageSize() - 1) & ~(static_cast<uintptr_t>(pageSize()) - 1);
}

int segmentProt(uint32_t flags) {
    int prot = 0;
    if ((flags & PF_R) != 0) prot |= PROT_READ;
    if ((flags & PF_W) != 0) prot |= PROT_WRITE;
    if ((flags & PF_X) != 0) prot |= PROT_EXEC;
    return prot == 0 ? PROT_READ : prot;
}

uintptr_t dynamicValue(const ElfW(Dyn) *dynamic, ElfW(Sxword) tag,
                       uintptr_t fallback = 0) {
    for (const ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; entry++) {
        if (entry->d_tag == tag) {
            return static_cast<uintptr_t>(entry->d_un.d_val);
        }
    }
    return fallback;
}

struct SymbolTable {
    const ElfW(Sym) *symbols = nullptr;
    size_t count = 0;
    const char *strings = nullptr;
};

bool configureSymbols(Image *image, ElfW(Dyn) *dynamic, uintptr_t base) {
    auto *symbols = reinterpret_cast<const ElfW(Sym) *>(
            base + dynamicValue(dynamic, DT_SYMTAB));
    auto *strings = reinterpret_cast<const char *>(
            base + dynamicValue(dynamic, DT_STRTAB));
    if (symbols == nullptr || strings == nullptr) {
        return false;
    }
    size_t count = 0;
    uintptr_t hash = dynamicValue(dynamic, DT_HASH);
    if (hash != 0) {
        auto *table = reinterpret_cast<const Elf32_Word *>(base + hash);
        count = table[1];
    } else {
        uintptr_t gnuHash = dynamicValue(dynamic, DT_GNU_HASH);
        if (gnuHash != 0) {
            auto *table = reinterpret_cast<const uint32_t *>(base + gnuHash);
            uint32_t buckets = table[0];
            uint32_t symbolOffset = table[1];
            uint32_t bloomSize = table[2];
#if defined(__LP64__)
            const uint32_t *bucketTable = table + 4 + bloomSize * 2;
#else
            const uint32_t *bucketTable = table + 4 + bloomSize;
#endif
            const uint32_t *chainTable = bucketTable + buckets;
            uint32_t maximum = symbolOffset;
            for (uint32_t index = 0; index < buckets; index++) {
                uint32_t symbol = bucketTable[index];
                if (symbol < symbolOffset) {
                    continue;
                }
                while (true) {
                    maximum = std::max(maximum, symbol);
                    if ((chainTable[symbol - symbolOffset] & 1u) != 0) {
                        break;
                    }
                    symbol++;
                }
            }
            count = static_cast<size_t>(maximum) + 1;
        }
    }
    if (count == 0) {
        return false;
    }
    image->symbols = symbols;
    image->symbolCount = count;
    image->strings = strings;
    return true;
}

void *lookupInImage(Image *image, const char *name) {
    if (image == nullptr || name == nullptr || image->symbols == nullptr) {
        return nullptr;
    }
    for (size_t index = 1; index < image->symbolCount; index++) {
        const ElfW(Sym) &symbol = image->symbols[index];
        if (symbol.st_shndx == SHN_UNDEF || symbol.st_name == 0) {
            continue;
        }
        const char *symbolName = image->strings + symbol.st_name;
        if (std::strcmp(symbolName, name) == 0) {
            return reinterpret_cast<void *>(
                    reinterpret_cast<uintptr_t>(image->base) + symbol.st_value);
        }
    }
    return nullptr;
}

void *resolveSymbol(Image *image, uint32_t index, const char *name) {
    if (name == nullptr || name[0] == '\0') {
        return nullptr;
    }
    if (index < image->symbolCount) {
        const ElfW(Sym) &symbol = image->symbols[index];
        if (symbol.st_shndx != SHN_UNDEF) {
            return reinterpret_cast<void *>(
                    reinterpret_cast<uintptr_t>(image->base) + symbol.st_value);
        }
    }
    {
        std::lock_guard<std::mutex> guard(gImagesLock);
        for (Image *candidate : gImages) {
            void *value = lookupInImage(candidate, name);
            if (value != nullptr) {
                return value;
            }
        }
    }
    return dlsym(RTLD_DEFAULT, name);
}

bool applyRelocation(Image *image, uintptr_t base, uint32_t symbolIndex,
                     uint32_t type, uintptr_t offset, intptr_t addend) {
    if (symbolIndex >= image->symbolCount) {
        return false;
    }
    const ElfW(Sym) &symbol = image->symbols[symbolIndex];
    const char *name = image->strings + symbol.st_name;
    void *resolved = resolveSymbol(image, symbolIndex, name);
#if defined(__LP64__)
    const bool resolvedOk = resolved != nullptr
            || ELF64_ST_BIND(symbol.st_info) == STB_WEAK;
#else
    const bool resolvedOk = resolved != nullptr
            || ELF32_ST_BIND(symbol.st_info) == STB_WEAK;
#endif
    uintptr_t target = base + offset;
    switch (type) {
#if defined(__aarch64__)
        case R_AARCH64_NONE:
            return true;
        case R_AARCH64_RELATIVE:
            *reinterpret_cast<uintptr_t *>(target) = base + addend;
            return true;
        case R_AARCH64_ABS64:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved) + addend;
            return true;
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved);
            return true;
        case R_AARCH64_IRELATIVE:
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(
                            reinterpret_cast<void *(*)()>(base + addend)());
            return true;
#ifdef R_AARCH64_COPY
        case R_AARCH64_COPY:
            if (!resolvedOk) {
                return false;
            }
            if (resolved != nullptr) {
                std::memcpy(reinterpret_cast<void *>(target), resolved,
                            image->symbols[symbolIndex].st_size);
            }
            return true;
#endif
#elif defined(__x86_64__)
        case R_X86_64_NONE:
            return true;
        case R_X86_64_RELATIVE:
            *reinterpret_cast<uintptr_t *>(target) = base + addend;
            return true;
        case R_X86_64_64:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved) + addend;
            return true;
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved);
            return true;
        case R_X86_64_IRELATIVE:
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(
                            reinterpret_cast<void *(*)()>(base + addend)());
            return true;
#ifdef R_X86_64_COPY
        case R_X86_64_COPY:
            if (!resolvedOk) {
                return false;
            }
            if (resolved != nullptr) {
                std::memcpy(reinterpret_cast<void *>(target), resolved,
                            image->symbols[symbolIndex].st_size);
            }
            return true;
#endif
#elif defined(__arm__)
        case R_ARM_NONE:
            return true;
        case R_ARM_RELATIVE:
            *reinterpret_cast<uintptr_t *>(target) = base + addend;
            return true;
        case R_ARM_ABS32:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved) + addend;
            return true;
        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved);
            return true;
        case R_ARM_IRELATIVE:
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(
                            reinterpret_cast<void *(*)()>(base + addend)());
            return true;
#ifdef R_ARM_COPY
        case R_ARM_COPY:
            if (!resolvedOk) {
                return false;
            }
            if (resolved != nullptr) {
                std::memcpy(reinterpret_cast<void *>(target), resolved,
                            image->symbols[symbolIndex].st_size);
            }
            return true;
#endif
#elif defined(__i386__)
        case R_386_NONE:
            return true;
        case R_386_RELATIVE:
            *reinterpret_cast<uintptr_t *>(target) = base + addend;
            return true;
        case R_386_32:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved) + addend;
            return true;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
            if (!resolvedOk) {
                return false;
            }
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(resolved);
            return true;
        case R_386_IRELATIVE:
            *reinterpret_cast<uintptr_t *>(target) =
                    reinterpret_cast<uintptr_t>(
                            reinterpret_cast<void *(*)()>(base + addend)());
            return true;
#ifdef R_386_COPY
        case R_386_COPY:
            if (!resolvedOk) {
                return false;
            }
            if (resolved != nullptr) {
                std::memcpy(reinterpret_cast<void *>(target), resolved,
                            image->symbols[symbolIndex].st_size);
            }
            return true;
#endif
#endif
        default:
            __android_log_print(ANDROID_LOG_WARN, kTag,
                                "unsupported relocation %u in %s", type,
                                image->name.c_str());
            return false;
    }
}

bool applyRela(Image *image, uintptr_t base, ElfW(Addr) rela, size_t size,
               size_t entrySize) {
    if (rela == 0 || size < entrySize || entrySize < sizeof(ElfW(Rela))) {
        return true;
    }
    auto *entries = reinterpret_cast<ElfW(Rela) *>(base + rela);
    size_t count = size / entrySize;
    for (size_t index = 0; index < count; index++) {
        ElfW(Rela) &entry = entries[index];
        uint32_t symbolIndex = FM_R_SYM(entry.r_info);
        uint32_t type = FM_R_TYPE(entry.r_info);
        if (!applyRelocation(image, base, symbolIndex, type, entry.r_offset,
                             static_cast<intptr_t>(entry.r_addend))) {
            return false;
        }
    }
    return true;
}

bool applyRel(Image *image, uintptr_t base, ElfW(Addr) rel, size_t size,
              size_t entrySize) {
    if (rel == 0 || size < entrySize || entrySize < sizeof(ElfW(Rel))) {
        return true;
    }
    auto *entries = reinterpret_cast<ElfW(Rel) *>(base + rel);
    size_t count = size / entrySize;
    for (size_t index = 0; index < count; index++) {
        ElfW(Rel) &entry = entries[index];
        uint32_t symbolIndex = ELF32_R_SYM(entry.r_info);
        uint32_t type = ELF32_R_TYPE(entry.r_info);
        uintptr_t addend = *reinterpret_cast<uintptr_t *>(
                base + entry.r_offset);
        if (!applyRelocation(image, base, symbolIndex, type, entry.r_offset,
                             static_cast<intptr_t>(addend))) {
            return false;
        }
    }
    return true;
}

void applyRelr(Image *image, uintptr_t base, ElfW(Addr) relr, size_t size) {
    (void) image;
    if (relr == 0 || size < sizeof(uintptr_t)) {
        return;
    }
    auto *entries = reinterpret_cast<uintptr_t *>(base + relr);
    size_t count = size / sizeof(uintptr_t);
    uintptr_t where = 0;
    for (size_t index = 0; index < count; index++) {
        uintptr_t entry = entries[index];
        if ((entry & 1u) == 0) {
            where = entry;
            *reinterpret_cast<uintptr_t *>(base + where) += base;
            where += sizeof(uintptr_t);
            continue;
        }
        for (int bit = 0; bit < static_cast<int>(sizeof(uintptr_t) * 8 - 1);
             bit++) {
            if ((entry & (static_cast<uintptr_t>(1) << (bit + 1))) != 0) {
                *reinterpret_cast<uintptr_t *>(
                        base + where + bit * sizeof(uintptr_t)) += base;
            }
        }
        where += (sizeof(uintptr_t) * 8 - 1) * sizeof(uintptr_t);
    }
}

void flushCode(uintptr_t start, size_t size) {
#if defined(__aarch64__) || defined(__arm__)
    __builtin___clear_cache(reinterpret_cast<char *>(start),
                            reinterpret_cast<char *>(start + size));
#else
    (void) start;
    (void) size;
#endif
}

}  // namespace

Image *load(const uint8_t *data, size_t size, const char *name) {
    if (data == nullptr || size < sizeof(ElfW(Ehdr))) {
        return nullptr;
    }
    const ElfW(Ehdr) *header = reinterpret_cast<const ElfW(Ehdr) *>(data);
    if (header->e_ident[EI_MAG0] != ELFMAG0
            || header->e_ident[EI_MAG1] != ELFMAG1
            || header->e_ident[EI_MAG2] != ELFMAG2
            || header->e_ident[EI_MAG3] != ELFMAG3
            || header->e_ident[EI_CLASS] !=
#if defined(__LP64__)
                    ELFCLASS64
#else
                    ELFCLASS32
#endif
            || header->e_ident[EI_DATA] != ELFDATA2LSB
            || header->e_type != ET_DYN) {
        return nullptr;
    }
    auto *programs = reinterpret_cast<const ElfW(Phdr) *>(
            data + header->e_phoff);
    uintptr_t maximum = 0;
    for (int index = 0; index < header->e_phnum; index++) {
        const ElfW(Phdr) &program = programs[index];
        if (program.p_type != PT_LOAD) {
            continue;
        }
        maximum = std::max(maximum, static_cast<uintptr_t>(
                program.p_vaddr + program.p_memsz));
    }
    if (maximum == 0) {
        return nullptr;
    }
    size_t mappedSize = alignUp(maximum);
    void *base = mmap(nullptr, mappedSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        return nullptr;
    }
    Image *image = new Image();
    image->base = base;
    image->mappedSize = mappedSize;
    image->name = name == nullptr ? "" : name;
    for (int index = 0; index < header->e_phnum; index++) {
        const ElfW(Phdr) &program = programs[index];
        if (program.p_type != PT_LOAD || program.p_memsz == 0) {
            continue;
        }
        if (program.p_offset + program.p_filesz > size
                || program.p_vaddr + program.p_memsz > mappedSize) {
            munmap(base, mappedSize);
            delete image;
            return nullptr;
        }
        std::memcpy(static_cast<uint8_t *>(base) + program.p_vaddr,
                    data + program.p_offset, program.p_filesz);
        std::memset(static_cast<uint8_t *>(base) + program.p_vaddr
                    + program.p_filesz, 0,
                    program.p_memsz - program.p_filesz);
        image->segments.push_back({
                static_cast<uintptr_t>(program.p_vaddr),
                static_cast<size_t>(program.p_memsz),
                segmentProt(program.p_flags)});
    }
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(base);
    ElfW(Addr) dynamicVaddr = 0;
    for (int index = 0; index < header->e_phnum; index++) {
        if (programs[index].p_type == PT_DYNAMIC) {
            dynamicVaddr = programs[index].p_vaddr;
            break;
        }
    }
#if defined(PT_GNU_RELRO)
    for (int index = 0; index < header->e_phnum; index++) {
        if (programs[index].p_type == PT_GNU_RELRO
                && programs[index].p_memsz > 0) {
            image->relroAddress = programs[index].p_vaddr;
            image->relroSize = programs[index].p_memsz;
            break;
        }
    }
#endif
    auto *dynamic = dynamicVaddr == 0
            ? nullptr
            : reinterpret_cast<ElfW(Dyn) *>(baseAddress + dynamicVaddr);
    if (dynamic == nullptr) {
        munmap(base, mappedSize);
        delete image;
        return nullptr;
    }
    if (!configureSymbols(image, dynamic, baseAddress)) {
        munmap(base, mappedSize);
        delete image;
        return nullptr;
    }
    bool relocated = true;
    relocated = applyRela(image, baseAddress, dynamicValue(dynamic, DT_RELA),
                          dynamicValue(dynamic, DT_RELASZ),
                          dynamicValue(dynamic, DT_RELAENT,
                                       sizeof(ElfW(Rela)))) && relocated;
    if (dynamicValue(dynamic, DT_PLTREL) == DT_REL) {
        relocated = applyRel(image, baseAddress,
                             dynamicValue(dynamic, DT_JMPREL),
                             dynamicValue(dynamic, DT_PLTRELSZ),
                             dynamicValue(dynamic, DT_RELENT,
                                          sizeof(ElfW(Rel)))) && relocated;
    } else {
        relocated = applyRela(image, baseAddress,
                              dynamicValue(dynamic, DT_JMPREL),
                              dynamicValue(dynamic, DT_PLTRELSZ),
                              dynamicValue(dynamic, DT_RELAENT,
                                           sizeof(ElfW(Rela)))) && relocated;
    }
    relocated = applyRel(image, baseAddress, dynamicValue(dynamic, DT_REL),
                         dynamicValue(dynamic, DT_RELSZ),
                         dynamicValue(dynamic, DT_RELENT,
                                      sizeof(ElfW(Rel)))) && relocated;
    if (!relocated) {
        munmap(base, mappedSize);
        delete image;
        return nullptr;
    }
#if defined(DT_RELR)
    applyRelr(image, baseAddress, dynamicValue(dynamic, DT_RELR),
              dynamicValue(dynamic, DT_RELRSZ));
#endif
    for (const SegmentInfo &segment : image->segments) {
        uintptr_t start = alignDown(baseAddress + segment.address);
        uintptr_t end = alignUp(baseAddress + segment.address
                                + segment.memorySize);
        mprotect(reinterpret_cast<void *>(start), end - start, segment.prot);
    }
    if (image->relroSize > 0) {
        uintptr_t start = alignDown(baseAddress + image->relroAddress);
        uintptr_t end = alignUp(baseAddress + image->relroAddress
                                + image->relroSize);
        mprotect(reinterpret_cast<void *>(start), end - start, PROT_READ);
    }
    uintptr_t init = dynamicValue(dynamic, DT_INIT);
    uintptr_t initArray = dynamicValue(dynamic, DT_INIT_ARRAY);
    size_t initArraySize = dynamicValue(dynamic, DT_INIT_ARRAYSZ);
    if (init != 0) {
        auto function = reinterpret_cast<void (*)()>(baseAddress + init);
        function();
    }
    if (initArray != 0 && initArraySize >= sizeof(uintptr_t)) {
        auto *functions = reinterpret_cast<uintptr_t *>(baseAddress + initArray);
        size_t count = initArraySize / sizeof(uintptr_t);
        for (size_t index = 0; index < count; index++) {
            if (functions[index] != 0) {
                reinterpret_cast<void (*)()>(functions[index])();
            }
        }
    }
    flushCode(baseAddress, mappedSize);
    {
        std::lock_guard<std::mutex> guard(gImagesLock);
        gImages.push_back(image);
    }
    __android_log_print(ANDROID_LOG_INFO, kTag, "loaded %s base=%p size=%zu",
                        image->name.c_str(), base, mappedSize);
    return image;
}

void *symbol(Image *image, const char *name) {
    return lookupInImage(image, name);
}

bool contains(const void *address) {
    if (address == nullptr) {
        return false;
    }
    uintptr_t value = reinterpret_cast<uintptr_t>(address);
    std::lock_guard<std::mutex> guard(gImagesLock);
    for (Image *image : gImages) {
        uintptr_t start = reinterpret_cast<uintptr_t>(image->base);
        if (value >= start && value < start + image->mappedSize) {
            return true;
        }
    }
    return false;
}

bool is_image(const void *handle) {
    if (handle == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> guard(gImagesLock);
    for (Image *image : gImages) {
        if (image == handle) {
            return true;
        }
    }
    return false;
}

void close(Image *image) {
    if (image == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> guard(gImagesLock);
        gImages.erase(std::remove(gImages.begin(), gImages.end(), image),
                      gImages.end());
    }
    if (image->base != nullptr) {
        munmap(image->base, image->mappedSize);
    }
    delete image;
}

}  // namespace forgemirror::elf

extern "C" __attribute__((visibility("default"))) bool
fm_elf_contains_address(const void *address) {
    return forgemirror::elf::contains(address);
}
