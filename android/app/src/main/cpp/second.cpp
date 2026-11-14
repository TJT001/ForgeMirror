#include <android/log.h>
#include <jni.h>

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *, void *) {
    __android_log_print(ANDROID_LOG_INFO, "DemoSecond", "JNI_OnLoad from demo2");
    return JNI_VERSION_1_6;
}

extern "C" int demo2_value() {
    return 7;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeSecond(JNIEnv *, jobject) {
    return demo2_value();
}
