#include <jni.h>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

extern "C" JNIEXPORT jstring JNICALL
Java_dev_forgemirror_demo_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeWrite(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    int fd = open(text, O_WRONLY | O_APPEND);
    int error = errno;
    if (fd >= 0) {
        close(fd);
    }
    env->ReleaseStringUTFChars(path, text);
    return fd >= 0 ? 0 : error;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeRead(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    int fd = open(text, O_RDONLY);
    int error = errno;
    if (fd >= 0) {
        close(fd);
    }
    env->ReleaseStringUTFChars(path, text);
    return fd >= 0 ? 0 : error;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeMmap(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    int fd = open(text, O_RDONLY);
    int error = 0;
    if (fd >= 0) {
        errno = 0;
        void* mapped = mmap(nullptr, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        error = mapped == MAP_FAILED ? errno : 0;
        if (mapped != MAP_FAILED) {
            munmap(mapped, 1);
        }
        close(fd);
    } else {
        error = errno;
    }
    env->ReleaseStringUTFChars(path, text);
    return error;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeSyscall(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    errno = 0;
    long fd = syscall(SYS_openat, AT_FDCWD, text, O_WRONLY | O_APPEND, 0);
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) {
        close(static_cast<int>(fd));
    }
    env->ReleaseStringUTFChars(path, text);
    return error;
}
