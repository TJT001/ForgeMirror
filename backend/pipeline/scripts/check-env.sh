#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"

echo "project: $ROOT"
echo "java: $(java -version 2>&1 | head -1)"
echo "gradle wrapper: $(grep distributionUrl "$ROOT/android/gradle/wrapper/gradle-wrapper.properties" | cut -d= -f2)"
echo "python: $(python3 --version 2>&1)"
echo "openssl: $(openssl version 2>&1)"
echo "cmake: $("$SDK/cmake/3.22.1/bin/cmake" --version 2>/dev/null | head -1)"

fail=0

check_dir() {
    if [ -d "$1" ]; then
        echo "ok: $2 ($1)"
    else
        echo "missing: $2 ($1)" >&2
        fail=1
    fi
}

check_dir "$SDK/platform-tools" "Android platform-tools"
check_dir "$SDK/build-tools/36.0.0" "Android build-tools 36.0.0"
check_dir "$SDK/platforms/android-37.0" "Android platform 37"
check_dir "$SDK/ndk/28.2.13676358" "Android NDK 28.2.13676358"
check_dir "$SDK/cmake/3.22.1" "Android CMake 3.22.1"

if python3 -c 'import cryptography; print("cryptography", cryptography.__version__)' 2>/dev/null; then
    :
else
    echo "missing: Python cryptography" >&2
    fail=1
fi

if pkg-config --exists openssl; then
    echo "ok: OpenSSL headers ($(pkg-config --modversion openssl))"
else
    echo "missing: OpenSSL headers (host C++ vector test will be skipped)" >&2
fi

if "$SDK/platform-tools/adb" devices | grep -q $'\tdevice$'; then
    echo "ok: Android device connected"
    "$SDK/platform-tools/adb" devices
else
    echo "warn: no Android device in 'device' state" >&2
fi

exit "$fail"
