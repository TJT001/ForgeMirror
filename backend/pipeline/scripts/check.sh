#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export PYTHONPATH="$ROOT/backend/pipeline"

python3 "$ROOT/backend/pipeline/scripts/gen_container_vectors.py"
python3 -m unittest discover -s "$ROOT/backend/tests/pipeline" -v

if pkg-config --exists openssl; then
    mkdir -p "$ROOT/backend/bin"
    c++ -std=c++17 -O2 -Wall -Wextra \
        "$ROOT/backend/tests/native/container_reader_test.cpp" \
        -o "$ROOT/backend/bin/container_reader_test" \
        $(pkg-config --cflags --libs openssl)
    "$ROOT/backend/bin/container_reader_test" "$ROOT/backend/tests/vectors/container/v2"
else
    echo "openssl not found; skipping C++ vector test" >&2
fi

(cd "$ROOT/android" && ./gradlew :shield:assembleDebug :app:assembleDebug --console=plain)
