#!/usr/bin/env sh
set -eu

tmp_list="$(mktemp)"
tmp_crlf="$(mktemp)"
trap 'rm -f "$tmp_list" "$tmp_crlf"' EXIT HUP INT TERM

git ls-files '*.sh' > "$tmp_list"

while IFS= read -r f; do
  [ -f "$f" ] || continue
  if LC_ALL=C grep -q "$(printf '\r')" "$f"; then
    printf '%s\n' "$f" >> "$tmp_crlf"
  fi
done < "$tmp_list"

if [ -s "$tmp_crlf" ]; then
  echo "[line-endings][ERROR] CRLF detected in shell scripts:"
  sed 's/^/ - /' "$tmp_crlf"
  exit 1
fi

echo "[line-endings] OK: no CRLF detected in tracked *.sh files."
