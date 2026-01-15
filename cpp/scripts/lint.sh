#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: cpp/scripts/lint.sh --build-dir <cmake-build-dir> [--fix]

Runs clang-tidy only on Floe project sources (cpp/src, cpp/tests),
excluding build output and vendored dependencies.

Arguments:
  --build-dir <dir>   CMake build directory that contains compile_commands.json
  --fix               Apply fixes (clang-tidy -fix -format)
EOF
}

BUILD_DIR=""
FIX="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="${2:-}"
      shift 2
      ;;
    --fix)
      FIX="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$BUILD_DIR" ]]; then
  # Best-effort default: pick the newest compile_commands.json under cpp/
  if command -v ls >/dev/null 2>&1; then
    CCDB="$(ls -t ./cmake-build-*/compile_commands.json 2>/dev/null | head -n 1 || true)"
    if [[ -n "${CCDB:-}" ]]; then
      BUILD_DIR="$(cd "$(dirname "$CCDB")" && pwd)"
    fi
  fi
fi

if [[ -z "$BUILD_DIR" ]]; then
  echo "Missing --build-dir and could not auto-detect a build directory." >&2
  echo "Hint: cmake -B cpp/cmake-build-debug && cmake --build cpp/cmake-build-debug" >&2
  exit 2
fi

if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
  echo "No compile_commands.json found in: $BUILD_DIR" >&2
  echo "Hint: configure with CMake (CMAKE_EXPORT_COMPILE_COMMANDS=ON)." >&2
  exit 2
fi

CLANG_TIDY="${CLANG_TIDY:-}"
if [[ -z "$CLANG_TIDY" ]]; then
  for cand in clang-tidy clang-tidy-19 clang-tidy-18 clang-tidy-17; do
    if command -v "$cand" >/dev/null 2>&1; then
      CLANG_TIDY="$cand"
      break
    fi
  done
fi

if [[ -z "$CLANG_TIDY" ]]; then
  # Common Homebrew locations (brew doesn't always link llvm binaries into PATH).
  for cand in \
    /opt/homebrew/opt/llvm/bin/clang-tidy \
    /usr/local/opt/llvm/bin/clang-tidy; do
    if [[ -x "$cand" ]]; then
      CLANG_TIDY="$cand"
      break
    fi
  done
fi

if [[ -z "$CLANG_TIDY" ]] && command -v brew >/dev/null 2>&1; then
  BREW_LLVM="$(brew --prefix llvm 2>/dev/null || true)"
  if [[ -n "${BREW_LLVM:-}" && -x "$BREW_LLVM/bin/clang-tidy" ]]; then
    CLANG_TIDY="$BREW_LLVM/bin/clang-tidy"
  fi
fi

if [[ -z "$CLANG_TIDY" ]]; then
  echo "clang-tidy not found. Install LLVM/clang-tools and retry." >&2
  echo "macOS (Homebrew): brew install llvm && export CLANG_TIDY=\"\$(brew --prefix llvm)/bin/clang-tidy\"" >&2
  exit 127
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Only lint translation units that are in the compilation database.
# (Running clang-tidy directly on headers is fragile because headers are not
# usually present in compile_commands.json.)
mapfile -t FILES < <(
  find \
    "$ROOT/src" "$ROOT/tests" \
    -type f \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' \) \
    -print \
    | sort
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No C++ sources found under $ROOT/{include,src,tests}" >&2
  exit 0
fi

ARGS=(
  -p "$BUILD_DIR"
)

EXTRA_ARGS=()
if [[ "$(uname -s)" == "Darwin" ]] && command -v xcrun >/dev/null 2>&1; then
  SDK_PATH="$(xcrun --show-sdk-path 2>/dev/null || true)"
  if [[ -n "${SDK_PATH:-}" ]]; then
    # Helps Homebrew clang-tidy find libc++ headers on macOS when the SDK path isn't
    # present in compile_commands.json.
    EXTRA_ARGS+=(--extra-arg=-isysroot --extra-arg="$SDK_PATH")
  fi
fi

if [[ "$FIX" == "1" ]]; then
  ARGS+=(-fix -format-style=file)
fi

echo "Using clang-tidy: $CLANG_TIDY"
echo "Build dir: $BUILD_DIR"
echo "Files: ${#FILES[@]}"

# Run once per file to keep output actionable and avoid scanning deps via file selection.
FAIL=0
for f in "${FILES[@]}"; do
  if ! "$CLANG_TIDY" "${ARGS[@]}" "${EXTRA_ARGS[@]}" "$f"; then
    FAIL=1
  fi
done

exit "$FAIL"
