#!/usr/bin/env sh
set -eu

tmp_list="$(mktemp)"
tmp_crlf="$(mktemp)"
trap 'rm -f "$tmp_list" "$tmp_crlf"' EXIT HUP INT TERM

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

find "$REPO_ROOT" -type f -name '*.sh' ! -path "$REPO_ROOT/.git/*" | sort > "$tmp_list"

while IFS= read -r f; do
  [ -f "$f" ] || continue
  if LC_ALL=C grep -q "$(printf '\r')" "$f"; then
    rel_path="${f#"$REPO_ROOT"/}"
    printf '%s\n' "$rel_path" >> "$tmp_crlf"
  fi
done < "$tmp_list"

if [ -s "$tmp_crlf" ]; then
  echo "[line-endings][ERROR] CRLF detected in shell scripts:"
  sed 's/^/ - /' "$tmp_crlf"
  exit 1
fi

echo "[line-endings] OK: no CRLF detected in *.sh files."
