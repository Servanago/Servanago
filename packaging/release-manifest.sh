#!/bin/bash
# Write and sign latest.json for a built package: packaging/release-manifest.sh bin/servanago_X.Y.Z_amd64.deb KEYFILE [--breaking]
# Run after `make deb`, before `gh release create`; attach the .deb, latest.json and latest.json.sig.
set -euo pipefail
deb=${1:?usage: release-manifest.sh DEB KEYFILE [--breaking]}
key=${2:?usage: release-manifest.sh DEB KEYFILE [--breaking]}
shift 2
cd "$(dirname "$0")/.."

ver=$(basename "$deb" | sed -E 's/^servanago_([0-9.]+)_.*/\1/')
args=(--deb "$deb" --notes "https://github.com/Servanago/Servanago/releases/tag/v$ver" "$@")
prev=$(git describe --tags --abbrev=0 --match 'v*' "$(git rev-list -n1 "v$ver" 2>/dev/null || echo HEAD)^" 2>/dev/null || true)
if [ -n "$prev" ] && [ -n "$(git diff --name-only "$prev" HEAD -- internal/store/migrations)" ]; then
    args+=(--schema-change)
fi

out=$(dirname "$deb")/latest.json
bin/servanago manifest build "${args[@]}" > "$out"
bin/servanago manifest sign "$key" "$out"
echo "wrote $out and $out.sig"
