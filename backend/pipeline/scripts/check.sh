#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export PYTHONPATH="$ROOT/backend/pipeline"

python3 "$ROOT/backend/pipeline/scripts/gen_container_vectors.py"
python3 "$ROOT/backend/pipeline/scripts/gen_vault_vectors.py"
python3 -m unittest discover -s "$ROOT/backend/tests/pipeline" -v

if [ -f "$ROOT/backend/tests/vectors/vault/container.fdx" ]; then
    mkdir -p "$ROOT/backend/bin/vault"
    VAULT="$ROOT/android/shield/src/main/cpp/vault"
    for source in fm_sha256 fm_aes fm_whitebox fm_vault; do
        cc -std=c11 -O2 -Wall -Wextra -Werror -I "$VAULT" \
            -c "$VAULT/$source.c" -o "$ROOT/backend/bin/vault/$source.o"
    done
    c++ -std=c++17 -O2 -Wall -Wextra -I "$VAULT" \
        "$ROOT/backend/tests/native/vault_test.cpp" \
        "$ROOT"/backend/bin/vault/*.o -o "$ROOT/backend/bin/vault/vault_test"
    "$ROOT/backend/bin/vault/vault_test" "$ROOT/backend/tests/vectors/vault"
else
    echo "vault vectors missing (JDK not found); skipping native vault test" >&2
fi

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
