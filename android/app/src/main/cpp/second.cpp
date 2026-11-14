#include <jni.h>

extern "C" JNIEXPORT jint JNICALL
Java_dev_forgemirror_demo_MainActivity_nativeSecond(JNIEnv *, jobject) {
    return 7;
}
