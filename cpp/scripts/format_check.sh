#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CLANG_FORMAT="${CLANG_FORMAT:-}"
if [[ -z "$CLANG_FORMAT" ]]; then
  for cand in clang-format clang-format-19 clang-format-18 clang-format-17 clang-format-16 clang-format-15 clang-format-14; do
    if command -v "$cand" >/dev/null 2>&1; then
      CLANG_FORMAT="$cand"
      break
    fi
  done
fi

if [[ -z "$CLANG_FORMAT" ]]; then
  echo "clang-format not found. Install it or set CLANG_FORMAT=/path/to/clang-format" >&2
  exit 127
fi

mapfile -t FILES < <(
  git ls-files \
    | grep -E '^cpp/(include|src|tests)/.*\.(h|hpp|c|cc|cpp|cxx)$' \
    | sort
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No C/C++ files found under cpp/{include,src,tests} (tracked by git)."
  exit 0
fi

echo "Using clang-format: $CLANG_FORMAT"
echo "Files: ${#FILES[@]}"

SUPPORTS_DRY_RUN=0
if "$CLANG_FORMAT" --help 2>/dev/null | grep -q -- '--dry-run'; then
  SUPPORTS_DRY_RUN=1
fi

FAIL=0
for f in "${FILES[@]}"; do
  if [[ "$SUPPORTS_DRY_RUN" == "1" ]]; then
    if ! "$CLANG_FORMAT" --style=file --dry-run --Werror "$f"; then
      FAIL=1
    fi
  else
    # Older clang-format uses -n for "dry run"
    if ! "$CLANG_FORMAT" --style=file -n --Werror "$f"; then
      FAIL=1
    fi
  fi
done

exit "$FAIL"

