#!/usr/bin/env bash
# Compile every docs snippet, then boot each server snippet with its
# placeholders filled in and require it to still be serving after a few
# seconds, so a config the SDK refuses at startup fails CI.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for snippet in docs/snippets/*.go; do
    go vet "./$snippet"
done

for snippet in docs/snippets/*.server.go; do
    grep -q 'func main()' "$snippet" || continue
    grep -q 'ListenAndServe' "$snippet" || continue
    name=$(basename "$snippet" .go)
    mkdir -p "$tmp/$name"
    sed -e 's|\${PATH}|/paid|g' -e 's|\${URL}|http://127.0.0.1:4567/paid|g' "$snippet" >"$tmp/$name/main.go"
    go build -o "$tmp/$name/bin" "$tmp/$name/main.go"
    "$tmp/$name/bin" >"$tmp/$name/log" 2>&1 &
    pid=$!
    sleep 3
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "::error::$snippet exited at startup:"
        cat "$tmp/$name/log"
        exit 1
    fi
    kill "$pid"
    wait "$pid" 2>/dev/null || true
done
echo "docs snippets OK"
