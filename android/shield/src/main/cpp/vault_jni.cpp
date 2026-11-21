#include <jni.h>
#include <stdlib.h>

#include "vault/fm_vault.h"

namespace {

bool copy_in(JNIEnv *env, jbyteArray array, uint8_t **out, jsize *length) {
    *length = env->GetArrayLength(array);
    *out = static_cast<uint8_t *>(malloc(*length > 0 ? *length : 1));
    if (*out == nullptr) {
        return false;
    }
    env->GetByteArrayRegion(array, 0, *length, reinterpret_cast<jbyte *>(*out));
    return true;
}

void throw_security(JNIEnv *env, const char *message) {
    jclass type = env->FindClass("java/lang/SecurityException");
    if (type != nullptr) {
        env->ThrowNew(type, message);
    }
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_forgemirror_shield_ShieldKeyVault_nativeInstall(
        JNIEnv *env, jclass, jbyteArray blob, jbyteArray table) {
    uint8_t *blob_bytes = nullptr;
    uint8_t *table_bytes = nullptr;
    jsize blob_len = 0;
    jsize table_len = 0;
    if (!copy_in(env, blob, &blob_bytes, &blob_len)
        || !copy_in(env, table, &table_bytes, &table_len)) {
        free(blob_bytes);
        free(table_bytes);
        return JNI_FALSE;
    }
    int status = fm_vault_install(blob_bytes, static_cast<size_t>(blob_len),
                                  table_bytes, static_cast<size_t>(table_len));
    free(blob_bytes);
    free(table_bytes);
    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_forgemirror_shield_ShieldKeyVault_nativeInstallRaw(
        JNIEnv *env, jclass, jbyteArray key) {
    uint8_t *bytes = nullptr;
    jsize length = 0;
    if (!copy_in(env, key, &bytes, &length)) {
        return JNI_FALSE;
    }
    int status = fm_vault_install_raw(bytes, static_cast<size_t>(length));
    if (bytes != nullptr) {
        for (jsize i = 0; i < length; i++) {
            bytes[i] = 0;
        }
    }
    free(bytes);
    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_forgemirror_shield_ShieldKeyVault_nativeDerive(
        JNIEnv *env, jclass, jint id, jbyteArray build_id) {
    uint8_t *salt = nullptr;
    jsize length = 0;
    if (!copy_in(env, build_id, &salt, &length) || length != 16) {
        free(salt);
        throw_security(env, "bad build id");
        return nullptr;
    }
    uint8_t key[32];
    int status = fm_vault_derive(id, salt, key);
    free(salt);
    if (status != 0) {
        throw_security(env, "key vault not installed");
        return nullptr;
    }
    jbyteArray out = env->NewByteArray(32);
    if (out != nullptr) {
        env->SetByteArrayRegion(out, 0, 32, reinterpret_cast<jbyte *>(key));
    }
    for (int i = 0; i < 32; i++) {
        key[i] = 0;
    }
    return out;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_dev_forgemirror_shield_ShieldKeyVault_nativeOpenContainer(
        JNIEnv *env, jclass, jbyteArray container) {
    uint8_t *bytes = nullptr;
    jsize length = 0;
    if (!copy_in(env, container, &bytes, &length)) {
        throw_security(env, "container allocation failed");
        return nullptr;
    }
    fm_file *files = nullptr;
    int count = 0;
    int status = fm_container_open(bytes, static_cast<size_t>(length),
                                   &files, &count);
    free(bytes);
    if (status != 0) {
        throw_security(env, "container open failed");
        return nullptr;
    }
    jclass byte_array = env->FindClass("[B");
    jobjectArray result = env->NewObjectArray(count, byte_array, nullptr);
    if (result == nullptr) {
        fm_container_free(files, count);
        return nullptr;
    }
    for (int i = 0; i < count; i++) {
        jbyteArray item = env->NewByteArray(static_cast<jsize>(files[i].size));
        if (item == nullptr) {
            fm_container_free(files, count);
            throw_security(env, "out of memory");
            return nullptr;
        }
        env->SetByteArrayRegion(item, 0, static_cast<jsize>(files[i].size),
                                reinterpret_cast<jbyte *>(files[i].data));
        env->SetObjectArrayElement(result, i, item);
        env->DeleteLocalRef(item);
        if (env->ExceptionCheck()) {
            fm_container_free(files, count);
            return nullptr;
        }
    }
    fm_container_free(files, count);
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_dev_forgemirror_shield_ShieldKeyVault_nativeClear(JNIEnv *, jclass) {
    fm_vault_clear();
}
