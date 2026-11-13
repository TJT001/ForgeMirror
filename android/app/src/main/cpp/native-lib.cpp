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

extern "C" JNIEXPORT jstring JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeText(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return env->NewStringUTF("");
    }
    int fd = open(text, O_RDONLY);
    char buffer[33];
    int read = -1;
    if (fd >= 0) {
        read = static_cast<int>(::read(fd, buffer, sizeof(buffer) - 1));
        close(fd);
    }
    env->ReleaseStringUTFChars(path, text);
    if (read < 0) {
        return env->NewStringUTF("");
    }
    buffer[read] = '\0';
    return env->NewStringUTF(buffer);
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeWriteText(
        JNIEnv* env,
        jobject /* this */,
        jstring path,
        jstring value) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    const char* data = env->GetStringUTFChars(value, nullptr);
    if (text == nullptr || data == nullptr) {
        return -1;
    }
    int fd = open(text, O_RDWR);
    int error = 0;
    if (fd >= 0) {
        if (lseek(fd, 0, SEEK_SET) < 0 ||
            ::write(fd, data, strlen(data)) < 0) {
            error = errno;
        }
        close(fd);
    } else {
        error = errno;
    }
    env->ReleaseStringUTFChars(value, data);
    env->ReleaseStringUTFChars(path, text);
    return error;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeMmapWrite(
        JNIEnv* env,
        jobject /* this */,
        jstring path,
        jstring value) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    const char* data = env->GetStringUTFChars(value, nullptr);
    if (text == nullptr || data == nullptr) {
        return -1;
    }
    int fd = open(text, O_RDWR);
    int error = 0;
    if (fd >= 0) {
        size_t length = strlen(data);
        void* mapped = mmap(nullptr, length, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
        if (mapped == MAP_FAILED) {
            error = errno;
        } else {
            memcpy(mapped, data, length);
            if (msync(mapped, length, MS_SYNC) != 0) {
                error = errno;
            }
            munmap(mapped, length);
        }
        close(fd);
    } else {
        error = errno;
    }
    env->ReleaseStringUTFChars(value, data);
    env->ReleaseStringUTFChars(path, text);
    return error;
}
