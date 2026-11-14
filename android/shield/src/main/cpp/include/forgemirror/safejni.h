#pragma once

#include <jni.h>

namespace forgemirror::safejni {

inline bool hasException(JNIEnv *env) {
    return env != nullptr && env->ExceptionCheck() == JNI_TRUE;
}

inline bool clearException(JNIEnv *env) {
    if (!hasException(env)) {
        return false;
    }
    env->ExceptionClear();
    return true;
}

class LocalRef {
public:
    LocalRef(JNIEnv *env, jobject value) : env_(env), value_(value) {}

    ~LocalRef() {
        if (value_ != nullptr) {
            env_->DeleteLocalRef(value_);
        }
    }

    LocalRef(const LocalRef &) = delete;
    LocalRef &operator=(const LocalRef &) = delete;

    jobject get() const { return value_; }

private:
    JNIEnv *env_;
    jobject value_;
};

class Utf8String {
public:
    Utf8String(JNIEnv *env, jstring value)
            : env_(env), value_(value),
              chars_(value == nullptr ? nullptr
                                      : env->GetStringUTFChars(value, nullptr)) {}

    ~Utf8String() {
        if (chars_ != nullptr) {
            env_->ReleaseStringUTFChars(value_, chars_);
        }
    }

    Utf8String(const Utf8String &) = delete;
    Utf8String &operator=(const Utf8String &) = delete;

    const char *get() const { return chars_; }

private:
    JNIEnv *env_;
    jstring value_;
    const char *chars_;
};

class ByteArray {
public:
    ByteArray(JNIEnv *env, jbyteArray value)
            : env_(env), value_(value),
              data_(value == nullptr
                            ? nullptr
                            : env->GetByteArrayElements(value, nullptr)) {}

    ~ByteArray() {
        if (data_ != nullptr) {
            env_->ReleaseByteArrayElements(value_, data_, JNI_ABORT);
        }
    }

    ByteArray(const ByteArray &) = delete;
    ByteArray &operator=(const ByteArray &) = delete;

    jbyte *get() const { return data_; }

    jsize size() const {
        return value_ == nullptr ? 0 : env_->GetArrayLength(value_);
    }

private:
    JNIEnv *env_;
    jbyteArray value_;
    jbyte *data_;
};

inline jclass findClass(JNIEnv *env, const char *name) {
    jclass type = env->FindClass(name);
    if (type == nullptr) {
        clearException(env);
    }
    return type;
}

inline jmethodID staticMethod(JNIEnv *env, jclass type, const char *name,
                              const char *signature) {
    jmethodID method = env->GetStaticMethodID(type, name, signature);
    if (method == nullptr) {
        clearException(env);
    }
    return method;
}

inline jmethodID method(JNIEnv *env, jclass type, const char *name,
                        const char *signature) {
    jmethodID methodId = env->GetMethodID(type, name, signature);
    if (methodId == nullptr) {
        clearException(env);
    }
    return methodId;
}

inline jstring toString(JNIEnv *env, const char *value) {
    if (value == nullptr) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(value);
    if (result == nullptr) {
        clearException(env);
    }
    return result;
}

}  // namespace forgemirror::safejni
