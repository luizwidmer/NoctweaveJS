#!/usr/bin/env bash
set -euo pipefail

if ! command -v emcc >/dev/null 2>&1; then
  if [ -f "$HOME/emsdk/emsdk_env.sh" ]; then
    # shellcheck disable=SC1091
    . "$HOME/emsdk/emsdk_env.sh" >/dev/null
  fi
fi

command -v emcc >/dev/null 2>&1 || {
  echo "emcc was not found. Install Emscripten or source emsdk_env.sh first." >&2
  exit 1
}

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
JS_DIR="$ROOT_DIR/NoctweaveJS"
LIBOQS_DIR="$ROOT_DIR/NoctweaveCore/liboqs"
BUILD_DIR="$JS_DIR/wasm/build"
INSTALL_DIR="$BUILD_DIR/liboqs-install"
DIST_DIR="$JS_DIR/wasm/dist"
EXPECTED_LIBOQS_COMMIT="97f6b86b1b6d109cfd43cf276ae39c2e776aed80"
EXPECTED_EMSCRIPTEN_VERSION="6.0.1"

if [ ! -d "$LIBOQS_DIR/.git" ]; then
  echo "Pinned liboqs checkout is missing at $LIBOQS_DIR." >&2
  exit 1
fi

actual_liboqs_commit="$(git -C "$LIBOQS_DIR" rev-parse HEAD)"
if [ "$actual_liboqs_commit" != "$EXPECTED_LIBOQS_COMMIT" ]; then
  echo "Refusing to build from unreviewed liboqs commit $actual_liboqs_commit." >&2
  echo "Expected $EXPECTED_LIBOQS_COMMIT (liboqs 0.15.0)." >&2
  exit 1
fi

actual_emscripten_version="$(emcc --version | sed -n '1s/.*emcc.* \([0-9][0-9.]*\) .*/\1/p')"
if [ "$actual_emscripten_version" != "$EXPECTED_EMSCRIPTEN_VERSION" ]; then
  echo "Refusing a non-reproducible Emscripten toolchain: $actual_emscripten_version." >&2
  echo "Expected Emscripten $EXPECTED_EMSCRIPTEN_VERSION." >&2
  exit 1
fi

rm -rf "$BUILD_DIR/liboqs" "$INSTALL_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

emcmake cmake -S "$LIBOQS_DIR" -B "$BUILD_DIR/liboqs" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DOQS_DIST_BUILD=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DBUILD_SHARED_LIBS=OFF

cmake --build "$BUILD_DIR/liboqs" --parallel
cmake --install "$BUILD_DIR/liboqs"

LIBOQS_A="$INSTALL_DIR/lib/liboqs.a"
if [ ! -f "$LIBOQS_A" ]; then
  LIBOQS_A="$INSTALL_DIR/lib64/liboqs.a"
fi

if [ ! -f "$LIBOQS_A" ]; then
  echo "Could not locate liboqs.a under $INSTALL_DIR" >&2
  exit 1
fi

emcc "$JS_DIR/wasm/noctweave_oqs_shim.c" "$LIBOQS_A" \
  -I "$INSTALL_DIR/include" \
  -O3 \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s ENVIRONMENT=web,worker,node \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s STACK_SIZE=1048576 \
  -s INITIAL_MEMORY=33554432 \
  -s EXPORTED_FUNCTIONS='["_malloc","_free","_noctweave_oqs_init","_noctweave_oqs_profile_json","_noctweave_kem_public_key_length","_noctweave_kem_secret_key_length","_noctweave_kem_ciphertext_length","_noctweave_kem_shared_secret_length","_noctweave_sig_public_key_length","_noctweave_sig_secret_key_length","_noctweave_sig_signature_length","_noctweave_kem_keypair","_noctweave_kem_encaps","_noctweave_kem_decaps","_noctweave_sig_keypair","_noctweave_sig_sign","_noctweave_sig_verify","_noctweave_memzero"]' \
  -s EXPORTED_RUNTIME_METHODS='["HEAPU8","HEAPU32"]' \
  -o "$DIST_DIR/noctweave_oqs.js"

echo "Built $DIST_DIR/noctweave_oqs.js"
