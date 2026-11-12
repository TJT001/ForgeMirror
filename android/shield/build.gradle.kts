plugins { alias(libs.plugins.android.library) }

android {
    namespace = "dev.forgemirror.shield"
    compileSdk { version = release(37) }
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        externalNativeBuild { cmake { arguments += "-DCMAKE_CXX_STANDARD=17" } }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
}
