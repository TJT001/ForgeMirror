#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/openat2.h>

#include <shadowhook.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char *kTag = "ShieldHook";
constexpr int kMaxFds = 1024;
constexpr size_t kMaxPath = 512;

std::mutex gLock;
std::string gDataDir;
std::atomic<bool> gEnforce{false};
std::atomic<bool> gInstalled{false};
std::atomic<bool> gBlockAll{false};
std::atomic<bool> gBlockWrites{false};
std::string gFdPaths[kMaxFds];
JavaVM *gVm = nullptr;
jclass gIoClass = nullptr;
jmethodID gIoOpen = nullptr;
jmethodID gIoSync = nullptr;
__thread bool gInternal = false;
std::mutex gShadowLock;
std::unordered_set<int> gShadowFds;

struct ShadowMap {
    void *addr;
    size_t length;
    int fd;
};
std::vector<ShadowMap> gShadowMaps;
std::mutex gDirtyLock;
std::unordered_set<int> gDirtyFds;
std::atomic<bool> gSchedulerStarted{false};

bool is_covered(const char *path);
bool deny_now();
void java_sync_shadow(int fd, bool close);
bool write_flags(int flags);

using open_t = int (*)(const char *, int, ...);
using openat_t = int (*)(int, const char *, int, ...);
using open2_t = int (*)(const char *, int);
using openat2_t = int (*)(int, const char *, int);
using openat2_how_t = int (*)(int, const char *, struct open_how *, size_t);
using close_t = int (*)(int);
using rename_t = int (*)(const char *, const char *);
using renameat_t = int (*)(int, const char *, int, const char *);
using unlink_t = int (*)(const char *);
using unlinkat_t = int (*)(int, const char *, int);
using truncate_t = int (*)(const char *, off_t);
using ftruncate_t = int (*)(int, off_t);
using mmap_t = void *(*)(void *, size_t, int, int, int, off_t);
using mmap64_t = void *(*)(void *, size_t, int, int, int, off64_t);
using fsync_t = int (*)(int);
using munmap_t = int (*)(void *, size_t);
using msync_t = int (*)(void *, size_t, int);
using write_t = ssize_t (*)(int, const void *, size_t);
using pwrite64_t = ssize_t (*)(int, const void *, size_t, off64_t);
using writev_t = ssize_t (*)(int, const struct iovec *, int);
#if defined(__aarch64__)
using syscall_t = long (*)(long, ...);
#endif

open_t g_open = nullptr;
openat_t g_openat = nullptr;
open2_t g_open2 = nullptr;
openat2_t g_openat2 = nullptr;
openat2_how_t g_openat2_how = nullptr;
open_t g_open64 = nullptr;
openat_t g_openat64 = nullptr;
close_t g_close = nullptr;
rename_t g_rename = nullptr;
renameat_t g_renameat = nullptr;
unlink_t g_unlink = nullptr;
unlinkat_t g_unlinkat = nullptr;
truncate_t g_truncate = nullptr;
ftruncate_t g_ftruncate = nullptr;
mmap_t g_mmap = nullptr;
mmap64_t g_mmap64 = nullptr;
fsync_t g_fsync = nullptr;
fsync_t g_fdatasync = nullptr;
munmap_t g_munmap = nullptr;
msync_t g_msync = nullptr;
write_t g_write = nullptr;
pwrite64_t g_pwrite64 = nullptr;
writev_t g_writev = nullptr;
#if defined(__aarch64__)
syscall_t g_syscall = nullptr;
#endif

bool is_shadow(int fd) {
    std::lock_guard<std::mutex> guard(gShadowLock);
    return gShadowFds.find(fd) != gShadowFds.end();
}

void remember_shadow(int fd) {
    std::lock_guard<std::mutex> guard(gShadowLock);
    gShadowFds.insert(fd);
}

void forget_shadow(int fd) {
    {
        std::lock_guard<std::mutex> guard(gShadowLock);
        gShadowFds.erase(fd);
    }
    std::lock_guard<std::mutex> guard(gDirtyLock);
    gDirtyFds.erase(fd);
}

void mark_dirty(int fd) {
    if (!is_shadow(fd)) {
        return;
    }
    std::lock_guard<std::mutex> guard(gDirtyLock);
    gDirtyFds.insert(fd);
}

std::vector<int> take_dirty() {
    std::lock_guard<std::mutex> guard(gDirtyLock);
    std::vector<int> dirty(gDirtyFds.begin(), gDirtyFds.end());
    gDirtyFds.clear();
    return dirty;
}

void start_sync_scheduler() {
    bool expected = false;
    if (!gSchedulerStarted.compare_exchange_strong(expected, true)) {
        return;
    }
    std::thread([] {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            for (int fd : take_dirty()) {
                java_sync_shadow(fd, false);
            }
        }
    }).detach();
}

void remember_map(void *addr, size_t length, int fd) {
    std::lock_guard<std::mutex> guard(gShadowLock);
    gShadowMaps.push_back({addr, length, fd});
}

std::vector<int> take_maps(void *addr, size_t length, bool remove) {
    std::vector<int> fds;
    std::lock_guard<std::mutex> guard(gShadowLock);
    for (auto it = gShadowMaps.begin(); it != gShadowMaps.end();) {
        uintptr_t start = reinterpret_cast<uintptr_t>(it->addr);
        uintptr_t end = start + it->length;
        uintptr_t target = reinterpret_cast<uintptr_t>(addr);
        if (target < end && start < target + length) {
            fds.push_back(it->fd);
            if (remove) {
                it = gShadowMaps.erase(it);
                continue;
            }
        }
        ++it;
    }
    return fds;
}

int java_open_plaintext(const char *path, bool writable) {
    if (gVm == nullptr || gIoClass == nullptr || gIoOpen == nullptr) {
        return -1;
    }
    JNIEnv *env = nullptr;
    bool attached = false;
    jint status = gVm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if (gVm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return -1;
        }
        attached = true;
    } else if (status != JNI_OK) {
        return -1;
    }
    gInternal = true;
    jstring target = env->NewStringUTF(path);
    jint fd = -1;
    if (target != nullptr) {
        fd = env->CallStaticIntMethod(gIoClass, gIoOpen, target,
                                      writable ? JNI_TRUE : JNI_FALSE);
    }
    if (target != nullptr) {
        env->DeleteLocalRef(target);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        fd = -1;
    }
    gInternal = false;
    if (attached) {
        gVm->DetachCurrentThread();
    }
    return fd;
}

void java_sync_shadow(int fd, bool close) {
    if (gVm == nullptr || gIoClass == nullptr || gIoSync == nullptr) {
        return;
    }
    JNIEnv *env = nullptr;
    bool attached = false;
    jint status = gVm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if (gVm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            return;
        }
        attached = true;
    } else if (status != JNI_OK) {
        return;
    }
    gInternal = true;
    env->CallStaticVoidMethod(gIoClass, gIoSync, static_cast<jint>(fd),
                              close ? JNI_TRUE : JNI_FALSE);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    gInternal = false;
    if (attached) {
        gVm->DetachCurrentThread();
    }
}

int try_shadow_open(const char *path, int flags) {
    if (gInternal || path == nullptr || !is_covered(path) || !deny_now()) {
        return -1;
    }
    if ((flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 && access(path, F_OK) == 0) {
        errno = EEXIST;
        return -1;
    }
    int fd = java_open_plaintext(path, write_flags(flags));
    if (fd < 0) {
        return -1;
    }
    if ((flags & O_TRUNC) != 0) {
        if (g_ftruncate != nullptr) {
            g_ftruncate(fd, 0);
        }
    }
    if ((flags & O_APPEND) != 0) {
        int current = fcntl(fd, F_GETFL);
        if (current >= 0) {
            fcntl(fd, F_SETFL, current | O_APPEND);
        }
    }
    remember_shadow(fd);
    return fd;
}

bool is_covered(const char *path) {
    if (path == nullptr) {
        return false;
    }
    std::string prefix;
    {
        std::lock_guard<std::mutex> guard(gLock);
        if (gDataDir.empty()) {
            return false;
        }
        prefix = gDataDir;
    }
    const std::string files = prefix + "/files";
    const std::string prefs = prefix + "/shared_prefs";
    return strncmp(path, files.c_str(), files.size()) == 0 ||
           strncmp(path, prefs.c_str(), prefs.size()) == 0;
}

bool app_native_caller() {
    Dl_info info{};
    if (dladdr(shadowhook_get_return_address(), &info) == 0 || info.dli_fname == nullptr) {
        return false;
    }
    const char *name = info.dli_fname;
    if (strstr(name, "libshield") != nullptr ||
        strstr(name, "libshadowhook") != nullptr) {
        return false;
    }
    return strncmp(name, "/data/app/", 10) == 0 ||
           strncmp(name, "/data/data/", 11) == 0 ||
           strncmp(name, "/data/user/", 11) == 0;
}

bool deny_now() {
    return gEnforce.load(std::memory_order_relaxed) && app_native_caller();
}

std::string resolve_at(int dirfd, const char *path) {
    if (path == nullptr) {
        return {};
    }
    if (path[0] == '/') {
        return std::string(path);
    }
    if (dirfd == AT_FDCWD) {
        char cwd[kMaxPath];
        if (getcwd(cwd, sizeof(cwd)) != nullptr) {
            return std::string(cwd) + "/" + path;
        }
        return {};
    }
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);
    char target[kMaxPath];
    ssize_t length = readlink(link, target, sizeof(target) - 1);
    if (length <= 0) {
        return {};
    }
    target[length] = '\0';
    return std::string(target) + "/" + path;
}

void remember_fd(int fd, const char *path) {
    if (fd < 0 || fd >= kMaxFds || path == nullptr || !is_covered(path)) {
        return;
    }
    std::lock_guard<std::mutex> guard(gLock);
    gFdPaths[fd] = path;
}

void forget_fd(int fd) {
    if (fd < 0 || fd >= kMaxFds) {
        return;
    }
    std::lock_guard<std::mutex> guard(gLock);
    gFdPaths[fd].clear();
}

bool fd_covered(int fd, std::string *path) {
    if (fd < 0 || fd >= kMaxFds) {
        return false;
    }
    std::lock_guard<std::mutex> guard(gLock);
    if (gFdPaths[fd].empty()) {
        return false;
    }
    *path = gFdPaths[fd];
    return true;
}

bool write_flags(int flags) {
    return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

bool blocked_now(const std::string &resolved, int flags) {
    if (gInternal || resolved.empty() || !is_covered(resolved.c_str()) ||
        !app_native_caller()) {
        return false;
    }
    if (gBlockAll.load(std::memory_order_relaxed)) {
        return true;
    }
    return gBlockWrites.load(std::memory_order_relaxed) && write_flags(flags);
}

void log_deny(const char *operation, const char *path) {
    __android_log_print(ANDROID_LOG_WARN, kTag, "deny %s %s", operation,
                        path == nullptr ? "(null)" : path);
}


mode_t mode_from_args(int flags, va_list args) {
    if ((flags & O_CREAT) != 0) {
        return static_cast<mode_t>(va_arg(args, int));
    }
    return 0;
}

int proxy_open(const char *path, int flags, ...) {
    SHADOWHOOK_STACK_SCOPE();
    va_list args;
    va_start(args, flags);
    mode_t mode = mode_from_args(flags, args);
    va_end(args);
    std::string resolved = resolve_at(AT_FDCWD, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("open", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (open_t) shadowhook_get_prev_func((void *) &proxy_open);
    int fd = prev != nullptr ? prev(path, flags, mode) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}

int proxy_openat(int dirfd, const char *path, int flags, ...) {
    SHADOWHOOK_STACK_SCOPE();
    va_list args;
    va_start(args, flags);
    mode_t mode = mode_from_args(flags, args);
    va_end(args);
    std::string resolved = (path != nullptr && path[0] == '/')
            ? std::string(path) : resolve_at(dirfd, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("openat", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (openat_t) shadowhook_get_prev_func((void *) &proxy_openat);
    int fd = prev != nullptr ? prev(dirfd, path, flags, mode) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}

int proxy_open64(const char *path, int flags, ...) {
    SHADOWHOOK_STACK_SCOPE();
    va_list args;
    va_start(args, flags);
    mode_t mode = mode_from_args(flags, args);
    va_end(args);
    std::string resolved = resolve_at(AT_FDCWD, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("open64", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (open_t) shadowhook_get_prev_func((void *) &proxy_open64);
    int fd = prev != nullptr ? prev(path, flags, mode) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}

int proxy_openat64(int dirfd, const char *path, int flags, ...) {
    SHADOWHOOK_STACK_SCOPE();
    va_list args;
    va_start(args, flags);
    mode_t mode = mode_from_args(flags, args);
    va_end(args);
    std::string resolved = (path != nullptr && path[0] == '/')
            ? std::string(path) : resolve_at(dirfd, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("openat64", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (openat_t) shadowhook_get_prev_func((void *) &proxy_openat64);
    int fd = prev != nullptr ? prev(dirfd, path, flags, mode) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}

int proxy_open2(const char *path, int flags) {
    SHADOWHOOK_STACK_SCOPE();
    std::string resolved = resolve_at(AT_FDCWD, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("__open_2", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (open2_t) shadowhook_get_prev_func((void *) &proxy_open2);
    int fd = prev != nullptr ? prev(path, flags) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}

int proxy_openat2(int dirfd, const char *path, int flags) {
    SHADOWHOOK_STACK_SCOPE();
    std::string resolved = (path != nullptr && path[0] == '/')
            ? std::string(path) : resolve_at(dirfd, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            return shadow;
        }
        if (is_covered(resolved.c_str()) && deny_now()) {
            if (errno == EEXIST) {
                return -1;
            }
            errno = (write_flags(flags) || access(resolved.c_str(), F_OK) == 0)
                    ? EACCES : ENOENT;
            return -1;
        }
    }
    if (write_flags(flags) && !resolved.empty() && is_covered(resolved.c_str()) &&
        deny_now()) {
        log_deny("__openat_2", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (openat2_t) shadowhook_get_prev_func((void *) &proxy_openat2);
    int fd = prev != nullptr ? prev(dirfd, path, flags) : -1;
    if (fd >= 0 && !gInternal && !resolved.empty()) {
        remember_fd(fd, resolved.c_str());
    }
    return fd;
}


#if defined(__aarch64__)
long proxy_syscall(long number, ...) {
    SHADOWHOOK_STACK_SCOPE();
    va_list args;
    va_start(args, number);
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    long a6 = va_arg(args, long);
    va_end(args);

    bool deny = false;
    if (number == SYS_openat) {
        int dirfd = static_cast<int>(a1);
        const char *path = reinterpret_cast<const char *>(a2);
        int flags = static_cast<int>(a3);
        std::string resolved = (path != nullptr && path[0] == '/')
                ? std::string(path) : resolve_at(dirfd, path);
        if (!resolved.empty() && is_covered(resolved.c_str()) && deny_now()) {
            int shadow = try_shadow_open(resolved.c_str(), flags);
            if (shadow >= 0) {
                return shadow;
            }
            if (write_flags(flags)) {
                log_deny("syscall.openat", resolved.c_str());
                deny = true;
            }
        }
    }
#ifdef SYS_open
    else if (number == SYS_open) {
        const char *path = reinterpret_cast<const char *>(a1);
        int flags = static_cast<int>(a2);
        if (is_covered(path) && deny_now()) {
            int shadow = try_shadow_open(path, flags);
            if (shadow >= 0) {
                return shadow;
            }
            if (write_flags(flags)) {
                log_deny("syscall.open", path);
                deny = true;
            }
        }
    }
#endif
    else if (number == SYS_ftruncate) {
        int fd = static_cast<int>(a1);
        std::string path;
        if (!is_shadow(fd) && fd_covered(fd, &path) && deny_now()) {
            log_deny("syscall.ftruncate", path.c_str());
            deny = true;
        }
    }
#ifdef SYS_openat2
    else if (number == SYS_openat2) {
        int dirfd = static_cast<int>(a1);
        const char *path = reinterpret_cast<const char *>(a2);
        auto *how = reinterpret_cast<struct open_how *>(a3);
        size_t size = static_cast<size_t>(a4);
        if (how != nullptr && size >= sizeof(struct open_how)) {
            int flags = static_cast<int>(how->flags);
            std::string resolved = (path != nullptr && path[0] == '/')
                    ? std::string(path) : resolve_at(dirfd, path);
            if (!resolved.empty() && is_covered(resolved.c_str()) && deny_now()) {
                int shadow = try_shadow_open(resolved.c_str(), flags);
                if (shadow >= 0) {
                    return shadow;
                }
                if (write_flags(flags)) {
                    log_deny("syscall.openat2", resolved.c_str());
                    deny = true;
                }
            }
        }
    }
#endif
#ifdef SYS_mmap
    else if (number == SYS_mmap) {
        int prot = static_cast<int>(a3);
        int fd = static_cast<int>(a5);
        std::string path;
        if ((prot & PROT_WRITE) != 0 && !is_shadow(fd) && fd_covered(fd, &path) && deny_now()) {
            log_deny("syscall.mmap", path.c_str());
            deny = true;
        }
    }
#endif
    if (deny) {
        errno = EACCES;
        return -1;
    }
    auto prev = (syscall_t) shadowhook_get_prev_func((void *) &proxy_syscall);
    return prev != nullptr ? prev(number, a1, a2, a3, a4, a5, a6) : -1;
}

#endif
int proxy_fsync(int fd) {
    SHADOWHOOK_STACK_SCOPE();
    if (!gInternal && is_shadow(fd)) {
        java_sync_shadow(fd, false);
    }
    auto prev = (fsync_t) shadowhook_get_prev_func((void *) &proxy_fsync);
    return prev != nullptr ? prev(fd) : -1;
}

int proxy_munmap(void *addr, size_t length) {
    SHADOWHOOK_STACK_SCOPE();
    if (!gInternal) {
        std::vector<int> fds = take_maps(addr, length, true);
        for (int fd : fds) {
            java_sync_shadow(fd, false);
        }
    }
    auto prev = (munmap_t) shadowhook_get_prev_func((void *) &proxy_munmap);
    return prev != nullptr ? prev(addr, length) : -1;
}

int proxy_msync(void *addr, size_t length, int flags) {
    SHADOWHOOK_STACK_SCOPE();
    if (!gInternal) {
        std::vector<int> fds = take_maps(addr, length, false);
        for (int fd : fds) {
            java_sync_shadow(fd, false);
        }
    }
    auto prev = (msync_t) shadowhook_get_prev_func((void *) &proxy_msync);
    return prev != nullptr ? prev(addr, length, flags) : -1;
}

int proxy_openat2_how(int dirfd, const char *path, struct open_how *how, size_t size) {
    SHADOWHOOK_STACK_SCOPE();
    if (how == nullptr || size < sizeof(struct open_how)) {
        auto prev = (openat2_how_t) shadowhook_get_prev_func((void *) &proxy_openat2_how);
        return prev != nullptr ? prev(dirfd, path, how, size) : -1;
    }
    int flags = static_cast<int>(how->flags);
    std::string resolved = (path != nullptr && path[0] == '/')
            ? std::string(path) : resolve_at(dirfd, path);
    if (blocked_now(resolved, flags)) {
        log_deny("blocked.openat2", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    if (!gInternal && !resolved.empty() && is_covered(resolved.c_str()) && deny_now()) {
        int shadow = try_shadow_open(resolved.c_str(), flags);
        if (shadow >= 0) {
            if ((flags & O_TRUNC) != 0 && g_ftruncate != nullptr) {
                g_ftruncate(shadow, 0);
            }
            if ((flags & O_APPEND) != 0) {
                int current = fcntl(shadow, F_GETFL);
                if (current >= 0) {
                    fcntl(shadow, F_SETFL, current | O_APPEND);
                }
            }
            return shadow;
        }
        if (write_flags(flags) || access(resolved.c_str(), F_OK) == 0) {
            log_deny("openat2", resolved.c_str());
            errno = EACCES;
            return -1;
        }
        errno = ENOENT;
        return -1;
    }
    auto prev = (openat2_how_t) shadowhook_get_prev_func((void *) &proxy_openat2_how);
    return prev != nullptr ? prev(dirfd, path, how, size) : -1;
}

ssize_t proxy_write(int fd, const void *buffer, size_t count) {
    SHADOWHOOK_STACK_SCOPE();
    auto prev = (write_t) shadowhook_get_prev_func((void *) &proxy_write);
    ssize_t result = prev != nullptr ? prev(fd, buffer, count) : -1;
    if (result > 0) {
        mark_dirty(fd);
    }
    return result;
}

ssize_t proxy_pwrite64(int fd, const void *buffer, size_t count, off64_t offset) {
    SHADOWHOOK_STACK_SCOPE();
    auto prev = (pwrite64_t) shadowhook_get_prev_func((void *) &proxy_pwrite64);
    ssize_t result = prev != nullptr ? prev(fd, buffer, count, offset) : -1;
    if (result > 0) {
        mark_dirty(fd);
    }
    return result;
}

ssize_t proxy_writev(int fd, const struct iovec *iov, int count) {
    SHADOWHOOK_STACK_SCOPE();
    auto prev = (writev_t) shadowhook_get_prev_func((void *) &proxy_writev);
    ssize_t result = prev != nullptr ? prev(fd, iov, count) : -1;
    if (result > 0) {
        mark_dirty(fd);
    }
    return result;
}

int proxy_close(int fd) {
    SHADOWHOOK_STACK_SCOPE();
    if (!gInternal && is_shadow(fd)) {
        java_sync_shadow(fd, true);
        forget_shadow(fd);
    }
    forget_fd(fd);
    auto prev = (close_t) shadowhook_get_prev_func((void *) &proxy_close);
    return prev != nullptr ? prev(fd) : -1;
}

int proxy_rename(const char *from, const char *to) {
    SHADOWHOOK_STACK_SCOPE();
    if ((is_covered(from) || is_covered(to)) && deny_now()) {
        log_deny("rename", from);
        errno = EACCES;
        return -1;
    }
    auto prev = (rename_t) shadowhook_get_prev_func((void *) &proxy_rename);
    return prev != nullptr ? prev(from, to) : -1;
}

int proxy_renameat(int fromfd, const char *from, int tofd, const char *to) {
    SHADOWHOOK_STACK_SCOPE();
    std::string source = (from != nullptr && from[0] == '/')
            ? std::string(from) : resolve_at(fromfd, from);
    std::string target = (to != nullptr && to[0] == '/')
            ? std::string(to) : resolve_at(tofd, to);
    if ((is_covered(source.c_str()) || is_covered(target.c_str())) && deny_now()) {
        log_deny("renameat", source.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (renameat_t) shadowhook_get_prev_func((void *) &proxy_renameat);
    return prev != nullptr ? prev(fromfd, from, tofd, to) : -1;
}

int proxy_unlink(const char *path) {
    SHADOWHOOK_STACK_SCOPE();
    if (is_covered(path) && deny_now()) {
        log_deny("unlink", path);
        errno = EACCES;
        return -1;
    }
    auto prev = (unlink_t) shadowhook_get_prev_func((void *) &proxy_unlink);
    return prev != nullptr ? prev(path) : -1;
}

int proxy_unlinkat(int dirfd, const char *path, int flags) {
    SHADOWHOOK_STACK_SCOPE();
    std::string resolved = (path != nullptr && path[0] == '/')
            ? std::string(path) : resolve_at(dirfd, path);
    if (!resolved.empty() && is_covered(resolved.c_str()) && deny_now()) {
        log_deny("unlinkat", resolved.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (unlinkat_t) shadowhook_get_prev_func((void *) &proxy_unlinkat);
    return prev != nullptr ? prev(dirfd, path, flags) : -1;
}

int proxy_truncate(const char *path, off_t length) {
    SHADOWHOOK_STACK_SCOPE();
    if (is_covered(path) && deny_now()) {
        log_deny("truncate", path);
        errno = EACCES;
        return -1;
    }
    auto prev = (truncate_t) shadowhook_get_prev_func((void *) &proxy_truncate);
    return prev != nullptr ? prev(path, length) : -1;
}

int proxy_ftruncate(int fd, off_t length) {
    SHADOWHOOK_STACK_SCOPE();
    std::string path;
    if (!is_shadow(fd) && fd_covered(fd, &path) && deny_now()) {
        log_deny("ftruncate", path.c_str());
        errno = EACCES;
        return -1;
    }
    auto prev = (ftruncate_t) shadowhook_get_prev_func((void *) &proxy_ftruncate);
    int result = prev != nullptr ? prev(fd, length) : -1;
    if (result == 0) {
        mark_dirty(fd);
    }
    return result;
}

void *proxy_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    SHADOWHOOK_STACK_SCOPE();
    std::string path;
    if ((prot & PROT_WRITE) != 0 && !is_shadow(fd) && fd_covered(fd, &path) && deny_now()) {
        log_deny("mmap", path.c_str());
        errno = EACCES;
        return MAP_FAILED;
    }
    auto prev = (mmap_t) shadowhook_get_prev_func((void *) &proxy_mmap);
    void *result = prev != nullptr ? prev(addr, length, prot, flags, fd, offset) : MAP_FAILED;
    if (result != MAP_FAILED && (prot & PROT_WRITE) != 0 && is_shadow(fd)) {
        remember_map(result, length, fd);
        mark_dirty(fd);
    }
    return result;
}

void *proxy_mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    SHADOWHOOK_STACK_SCOPE();
    std::string path;
    if ((prot & PROT_WRITE) != 0 && !is_shadow(fd) && fd_covered(fd, &path) && deny_now()) {
        log_deny("mmap64", path.c_str());
        errno = EACCES;
        return MAP_FAILED;
    }
    auto prev = (mmap64_t) shadowhook_get_prev_func((void *) &proxy_mmap64);
    void *result = prev != nullptr ? prev(addr, length, prot, flags, fd, offset) : MAP_FAILED;
    if (result != MAP_FAILED && (prot & PROT_WRITE) != 0 && is_shadow(fd)) {
        remember_map(result, length, fd);
        mark_dirty(fd);
    }
    return result;
}

template <typename T>
int hook_one(const char *lib, const char *symbol, void *replacement) {
    void *stub = shadowhook_hook_sym_name(lib, symbol, replacement, nullptr);
    if (stub != nullptr) {
        __android_log_print(ANDROID_LOG_INFO, kTag, "hook %s in %s ok", symbol, lib);
        return 1;
    }
    return 0;
}

template <typename T>
void hook(const char *symbol, void *replacement, T *original) {
    (void) original;
    int installed = 0;
    const char *libs[] = {
        "libc.so",
        "/system/lib64/libc.so",
        "/system/lib/libc.so",
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib/bionic/libc.so",
    };
    for (const char *lib : libs) {
        installed += hook_one<T>(lib, symbol, replacement);
    }
    if (installed == 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag, "hook %s failed", symbol);
    }
}

void install() {
    int status = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
    if (status != 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag,
                            "shadowhook init failed: %d %s", status,
                            shadowhook_to_errmsg(shadowhook_get_init_errno()));
        return;
    }
    hook("open", reinterpret_cast<void *>(&proxy_open), &g_open);
    hook("openat", reinterpret_cast<void *>(&proxy_openat), &g_openat);
    hook("__open_2", reinterpret_cast<void *>(&proxy_open2), &g_open2);
    hook("__openat_2", reinterpret_cast<void *>(&proxy_openat2), &g_openat2);
    hook("openat2", reinterpret_cast<void *>(&proxy_openat2_how), &g_openat2_how);
    hook("open64", reinterpret_cast<void *>(&proxy_open64), &g_open64);
    hook("openat64", reinterpret_cast<void *>(&proxy_openat64), &g_openat64);
    hook("close", reinterpret_cast<void *>(&proxy_close), &g_close);
    hook("rename", reinterpret_cast<void *>(&proxy_rename), &g_rename);
    hook("renameat", reinterpret_cast<void *>(&proxy_renameat), &g_renameat);
    hook("unlink", reinterpret_cast<void *>(&proxy_unlink), &g_unlink);
    hook("unlinkat", reinterpret_cast<void *>(&proxy_unlinkat), &g_unlinkat);
    hook("truncate", reinterpret_cast<void *>(&proxy_truncate), &g_truncate);
    hook("ftruncate", reinterpret_cast<void *>(&proxy_ftruncate), &g_ftruncate);
    hook("mmap", reinterpret_cast<void *>(&proxy_mmap), &g_mmap);
    hook("mmap64", reinterpret_cast<void *>(&proxy_mmap64), &g_mmap64);
    hook("munmap", reinterpret_cast<void *>(&proxy_munmap), &g_munmap);
    hook("msync", reinterpret_cast<void *>(&proxy_msync), &g_msync);
    hook("fsync", reinterpret_cast<void *>(&proxy_fsync), &g_fsync);
    hook("fdatasync", reinterpret_cast<void *>(&proxy_fsync), &g_fdatasync);
#if defined(__aarch64__)
    hook("syscall", reinterpret_cast<void *>(&proxy_syscall), &g_syscall);
#endif
    hook("write", reinterpret_cast<void *>(&proxy_write), &g_write);
    hook("pwrite64", reinterpret_cast<void *>(&proxy_pwrite64), &g_pwrite64);
    hook("writev", reinterpret_cast<void *>(&proxy_writev), &g_writev);
    start_sync_scheduler();
    gInstalled.store(true, std::memory_order_release);
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_shield_ShieldNativeFileHook_nativeConfigure(
    JNIEnv *env, jclass type, jstring dataDir, jboolean enforce) {
    (void) type;
    if (dataDir == nullptr) {
        return -1;
    }
    const char *dir = env->GetStringUTFChars(dataDir, nullptr);
    if (dir == nullptr) {
        return -1;
    }
    {
        std::lock_guard<std::mutex> guard(gLock);
        gDataDir = dir;
    }
    env->ReleaseStringUTFChars(dataDir, dir);
    gEnforce.store(enforce == JNI_TRUE, std::memory_order_release);
    static std::once_flag once;
    std::call_once(once, install);
    return gInstalled.load(std::memory_order_acquire) ? 0 : -1;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_forgemirror_shield_ShieldNativeFileHook_nativeInstalled(
    JNIEnv *env, jclass type) {
    (void) env;
    (void) type;
    return gInstalled.load(std::memory_order_acquire) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    gVm = vm;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass type = env->FindClass("dev/forgemirror/shield/ShieldNativeIo");
    if (type != nullptr) {
        gIoClass = static_cast<jclass>(env->NewGlobalRef(type));
        gIoOpen = env->GetStaticMethodID(gIoClass, "open", "(Ljava/lang/String;Z)I");
        gIoSync = env->GetStaticMethodID(gIoClass, "sync", "(IZ)V");
        if (gIoOpen == nullptr || gIoSync == nullptr) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(type);
    } else {
        env->ExceptionClear();
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
Java_dev_forgemirror_shield_ShieldNativeFileHook_nativeSetBlockMode(
    JNIEnv *env, jclass type, jint mode) {
    (void) env;
    (void) type;
    gBlockAll.store(mode >= 2, std::memory_order_release);
    gBlockWrites.store(mode == 1, std::memory_order_release);
    __android_log_print(ANDROID_LOG_WARN, kTag, "block-mode=%d", mode);
}
