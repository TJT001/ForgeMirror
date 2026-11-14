#include <android/dlext.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>

#include "forgemirror/safejni.h"

namespace {

constexpr const char *kTag = "ShieldNativeLoader";

int create_memfd(const uint8_t *data, size_t size) {
    int fd = static_cast<int>(syscall(SYS_memfd_create, "fm-native", 0));
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_WARN, kTag, "memfd_create failed: %d", errno);
        return -1;
    }
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = ::write(fd, data + offset, size - offset);
        if (written <= 0) {
            __android_log_print(ANDROID_LOG_WARN, kTag, "memfd write failed: %d", errno);
            ::close(fd);
            return -1;
        }
        offset += static_cast<size_t>(written);
    }
    if (::lseek(fd, 0, SEEK_SET) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_dev_forgemirror_shield_ShieldNativeLoader_nativeLoad(
        JNIEnv *env, jclass /* type */, jbyteArray bytes, jstring name) {
    forgemirror::safejni::ByteArray data(env, bytes);
    if (data.get() == nullptr || data.size() <= 0) {
        forgemirror::safejni::clearException(env);
        return 0;
    }
    int fd = create_memfd(reinterpret_cast<const uint8_t *>(data.get()),
                          static_cast<size_t>(data.size()));
    if (fd < 0) {
        return 0;
    }
    forgemirror::safejni::Utf8String label(env, name);
    android_dlextinfo info{};
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    info.library_fd = fd;
    void *handle = android_dlopen_ext(
            label.get() == nullptr ? "fm-native" : label.get(), RTLD_NOW, &info);
    int error = handle == nullptr ? errno : 0;
    ::close(fd);
    if (handle == nullptr) {
        __android_log_print(ANDROID_LOG_WARN, kTag, "dlopen failed: %d", error);
        return 0;
    }
    return reinterpret_cast<jlong>(handle);
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_forgemirror_shield_ShieldRuntime_nativeLoadInMemory(
        JNIEnv *env, jclass /* type */, jbyteArray bytes, jstring name) {
    return Java_dev_forgemirror_shield_ShieldNativeLoader_nativeLoad(
            env, nullptr, bytes, name);
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_shield_ShieldNativeLoader_nativeRegister(
        JNIEnv *env, jclass /* type */, jclass caller, jobjectArray names,
        jobjectArray signatures, jobjectArray symbols, jlong handle) {
    if (caller == nullptr || names == nullptr || signatures == nullptr
            || symbols == nullptr || handle == 0) {
        return -1;
    }
    jsize count = env->GetArrayLength(names);
    if (count <= 0) {
        return 0;
    }
    jint registered = 0;
    for (jsize index = 0; index < count; index++) {
        jstring name = static_cast<jstring>(
                env->GetObjectArrayElement(names, index));
        jstring signature = static_cast<jstring>(
                env->GetObjectArrayElement(signatures, index));
        jstring symbol = static_cast<jstring>(
                env->GetObjectArrayElement(symbols, index));
        forgemirror::safejni::Utf8String nameText(env, name);
        forgemirror::safejni::Utf8String signatureText(env, signature);
        forgemirror::safejni::Utf8String symbolText(env, symbol);
        if (nameText.get() != nullptr && signatureText.get() != nullptr
                && symbolText.get() != nullptr) {
            void *address = dlsym(reinterpret_cast<void *>(handle), symbolText.get());
            if (address != nullptr) {
                JNINativeMethod method{
                        const_cast<char *>(nameText.get()),
                        const_cast<char *>(signatureText.get()), address};
                if (env->RegisterNatives(caller, &method, 1) == JNI_OK) {
                    registered++;
                }
            }
        }
        // Local references are released with the JNI local frame.
    }
    return registered;
}
