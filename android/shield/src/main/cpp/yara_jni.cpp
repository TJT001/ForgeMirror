#include <jni.h>

#include <yara.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

struct CompileResult {
    YR_RULES* rules = nullptr;
    std::string error;
};

void compiler_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data) {
    (void) error_level;
    (void) file_name;
    (void) rule;
    auto* result = static_cast<CompileResult*>(user_data);
    if (result == nullptr || message == nullptr) {
        return;
    }
    if (line_number > 0) {
        result->error += "line ";
        result->error += std::to_string(line_number);
        result->error += ": ";
    }
    result->error += message;
    result->error += "\n";
}

int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data) {
    (void) context;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);
        auto* matches = static_cast<std::vector<std::string>*>(user_data);
        if (rule != nullptr && matches != nullptr && rule->identifier != nullptr) {
            matches->emplace_back(rule->identifier);
        }
    }
    return CALLBACK_CONTINUE;
}

void throw_illegal(JNIEnv* env, const std::string& message) {
    jclass type = env->FindClass("java/lang/IllegalArgumentException");
    if (type != nullptr) {
        env->ThrowNew(type, message.c_str());
    }
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void) vm;
    (void) reserved;
    if (yr_initialize() != ERROR_SUCCESS) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    (void) vm;
    (void) reserved;
    yr_finalize();
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_forgemirror_shield_ShieldYara_nativeCompile(
    JNIEnv* env, jclass type, jstring source) {
    (void) type;
    if (source == nullptr) {
        return 0;
    }
    const char* text = env->GetStringUTFChars(source, nullptr);
    if (text == nullptr) {
        return 0;
    }
    CompileResult result;
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS || compiler == nullptr) {
        env->ReleaseStringUTFChars(source, text);
        throw_illegal(env, "YARA compiler initialization failed");
        return 0;
    }
    yr_compiler_set_callback(compiler, compiler_callback, &result);
    int errors = yr_compiler_add_string(compiler, text, nullptr);
    env->ReleaseStringUTFChars(source, text);
    if (errors != 0) {
        std::string message = result.error.empty()
            ? "YARA compile failed" : result.error;
        yr_compiler_destroy(compiler);
        throw_illegal(env, message);
        return 0;
    }
    if (yr_compiler_get_rules(compiler, &result.rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        throw_illegal(env, "YARA rule extraction failed");
        return 0;
    }
    yr_compiler_destroy(compiler);
    return static_cast<jlong>(reinterpret_cast<intptr_t>(result.rules));
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_dev_forgemirror_shield_ShieldYara_nativeScan(
    JNIEnv* env, jclass type, jlong handle, jbyteArray data) {
    (void) type;
    jclass string_type = env->FindClass("java/lang/String");
    if (string_type == nullptr) {
        return nullptr;
    }
    jobjectArray empty = env->NewObjectArray(0, string_type, nullptr);
    auto* rules = reinterpret_cast<YR_RULES*>(static_cast<intptr_t>(handle));
    if (rules == nullptr || data == nullptr) {
        return empty;
    }
    jsize length = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    if (bytes == nullptr) {
        return empty;
    }
    std::vector<std::string> matches;
    int status = yr_rules_scan_mem(
        rules,
        reinterpret_cast<const uint8_t*>(bytes),
        static_cast<size_t>(length),
        0,
        scan_callback,
        &matches,
        0);
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    if (status != ERROR_SUCCESS) {
        throw_illegal(env, "YARA scan failed");
        return nullptr;
    }
    jobjectArray output = env->NewObjectArray(
        static_cast<jsize>(matches.size()), string_type, nullptr);
    if (output == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < matches.size(); index++) {
        jstring value = env->NewStringUTF(matches[index].c_str());
        if (value == nullptr) {
            return nullptr;
        }
        env->SetObjectArrayElement(output, static_cast<jsize>(index), value);
        env->DeleteLocalRef(value);
    }
    return output;
}

extern "C" JNIEXPORT void JNICALL
Java_dev_forgemirror_shield_ShieldYara_nativeDestroy(
    JNIEnv* env, jclass type, jlong handle) {
    (void) env;
    (void) type;
    auto* rules = reinterpret_cast<YR_RULES*>(static_cast<intptr_t>(handle));
    if (rules != nullptr) {
        yr_rules_destroy(rules);
    }
}
