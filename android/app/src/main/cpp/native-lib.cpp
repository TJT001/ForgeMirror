#include <jni.h>
#include <string>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <thread>

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
Java_dev_forgemirror_demo_MainActivity_nativeProbeOpenMerge(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    int fd = open(text, O_RDWR);
    env->ReleaseStringUTFChars(path, text);
    return fd >= 0 ? fd : -errno;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbePwrite(
        JNIEnv* env,
        jobject /* this */,
        jint fd,
        jint offset,
        jstring value) {
    const char* data = env->GetStringUTFChars(value, nullptr);
    if (data == nullptr) {
        return -1;
    }
    ssize_t written = ::pwrite(fd, data, strlen(data), offset);
    int error = written < 0 ? errno : 0;
    env->ReleaseStringUTFChars(value, data);
    return error;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeClose(
        JNIEnv* env,
        jobject /* this */,
        jint fd) {
    (void) env;
    return close(fd) == 0 ? 0 : errno;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeOverload__Ljava_lang_String_2(
        JNIEnv *, jobject, jstring) {
    return 11;
}

extern "C" int demo2_value();

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeDlopen(JNIEnv *, jobject) {
    void *handle = dlopen("libdemo2.so", RTLD_NOW);
    if (handle == nullptr) {
        return -1;
    }
    auto function = reinterpret_cast<int (*)()>(dlsym(handle, "demo2_value"));
    if (function == nullptr) {
        dlclose(handle);
        return -2;
    }
    int value = function();
    dlclose(handle);
    return value;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeDependency(JNIEnv *, jobject) {
    return demo2_value();
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeOverload__I(
        JNIEnv *, jobject, jint) {
    return 12;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeLock(
        JNIEnv* env,
        jobject /* this */,
        jstring path) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    if (text == nullptr) {
        return -1;
    }
    int first = open(text, O_RDWR);
    int second = open(text, O_RDWR);
    if (first < 0 || second < 0) {
        if (first >= 0) close(first);
        if (second >= 0) close(second);
        env->ReleaseStringUTFChars(path, text);
        return -1;
    }
    int flockFirst = ::flock(first, LOCK_EX | LOCK_NB);
    errno = 0;
    int flockSecond = ::flock(second, LOCK_EX | LOCK_NB);
    int flockErr = flockSecond == 0 ? 0 : errno;
    ::flock(first, LOCK_UN);
    ::flock(second, LOCK_UN);

    struct flock request{};
    request.l_type = F_WRLCK;
    request.l_whence = SEEK_SET;
    request.l_start = 0;
    request.l_len = 0;
    int fcntlFirst = fcntl(first, F_SETLK, &request);
    errno = 0;
    int fcntlSecond = fcntl(second, F_SETLK, &request);
    request.l_type = F_UNLCK;
    fcntl(first, F_SETLK, &request);
    fcntl(second, F_SETLK, &request);
    int result = 0;
    if (flockFirst != 0) {
        result = 201;
    } else if (fcntlFirst != 0) {
        result = 202;
    } else if (flockSecond == 0) {
        result = 203;
    }
#ifdef F_OFD_SETLK
    if (result == 0) {
        request.l_type = F_WRLCK;
        int ofdFirst = fcntl(first, F_OFD_SETLK, &request);
        errno = 0;
        int ofdSecond = fcntl(second, F_OFD_SETLK, &request);
        request.l_type = F_UNLCK;
        fcntl(first, F_OFD_SETLK, &request);
        fcntl(second, F_OFD_SETLK, &request);
        if (ofdFirst == 0 && ofdSecond == 0) {
            result = 205;
        }
    }
#endif
    close(first);
    close(second);
    env->ReleaseStringUTFChars(path, text);
    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeDupWrite(
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
        int copy = dup(fd);
        if (copy < 0) {
            error = errno;
            close(fd);
        } else {
            if (lseek(copy, 0, SEEK_SET) < 0 ||
                ::write(copy, data, strlen(data)) < 0) {
                error = errno;
            }
            close(fd);
            close(copy);
        }
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

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeProbeHoldWrite(
        JNIEnv* env,
        jobject /* this */,
        jstring path,
        jstring value,
        jint millis) {
    const char* text = env->GetStringUTFChars(path, nullptr);
    const char* data = env->GetStringUTFChars(value, nullptr);
    if (text == nullptr || data == nullptr) {
        return -1;
    }
    std::string target(text);
    std::string payload(data);
    env->ReleaseStringUTFChars(value, data);
    env->ReleaseStringUTFChars(path, text);
    std::thread([target, payload, millis] {
        int fd = open(target.c_str(), O_RDWR);
        if (fd >= 0) {
            ::write(fd, payload.data(), payload.size());
            std::this_thread::sleep_for(std::chrono::milliseconds(millis));
            close(fd);
        }
    }).detach();
    return 0;
}
