#!/usr/bin/env bash
# Build the connector bundle FortiSOAR installs:
# dist/fortinet-fortiedrv2-1_0_0.tgz, unpacking to a single
# fortinet-fortiedrv2/ directory.
#
# The FILENAME version uses underscores, not dots: FortiSOAR's installer
# misroutes a bundle whose name carries more than one dot, answering the
# misleading "Connector with same name is already active". One dot, exactly.
#
# Prefers git-tracked files; before the first commit it falls back to the
# working tree minus tests, packaging furniture and caches.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=$(python3 -c "import json;print(json.load(open('info.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('info.json'))['version'])")
FILE_VERSION=${VERSION//./_}
OUT="dist/${NAME}-${FILE_VERSION}.tgz"

EXCLUDE='^(\.git/|\.gitignore$|dist/|scripts/|tests/|README\.md$|release_notes\.md$|__pycache__/|.*\.pyc$|\.DS_Store$|\.github/|\.pytest_cache/|\.ruff_cache/|\.venv/|pyproject\.toml$|\.env)'

if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -n "$(git ls-files)" ]; then
    mapfile -t FILES < <(git ls-files | grep -Ev "$EXCLUDE")
else
    mapfile -t FILES < <(find . -type f \
        | sed 's|^\./||' \
        | grep -Ev "$EXCLUDE")
fi
if [ ${#FILES[@]} -eq 0 ]; then
    echo "package: no files matched" >&2
    exit 1
fi

for required in info.json connector.py operations.py requirements.txt models.py client.py field_mapping.py ingestion.py; do
    printf '%s\n' "${FILES[@]}" | grep -qx "$required" \
        || { echo "package: $required missing from the bundle" >&2; exit 1; }
done

rm -rf dist && mkdir -p "dist/stage/${NAME}"
for f in "${FILES[@]}"; do
    mkdir -p "dist/stage/${NAME}/$(dirname "$f")"
    cp "$f" "dist/stage/${NAME}/$(dirname "$f")/"
done
# latin-1 encode check: FortiSOAR loads connector sources as latin-1, so a
# non-latin-1 code point breaks the install on the appliance.
for f in $(printf '%s\n' "${FILES[@]}" | grep -E '\.(py|json|yaml|md|txt)$'); do
    python3 - "$f" <<'PY' || { echo "package: $f is not latin-1 safe" >&2; exit 1; }
import sys
open(sys.argv[1], encoding='utf-8').read().encode('latin-1')
PY
done
tar czf "$OUT" -C dist/stage "${NAME}"
rm -rf dist/stage

echo "$OUT ($(printf '%s\n' "${FILES[@]}" | wc -l | tr -d ' ') files, $(du -h "$OUT" | cut -f1))"
