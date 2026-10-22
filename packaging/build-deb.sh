#!/bin/bash
# Build the ServanaGo deb: build-deb.sh BIN [OUT].BIN and OUT may be absolute or repo-relative;
# the build never needs root (--root-owner-group) and the result is bin/servanago_<version>_<arch>.deb.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=${1:?usage: packaging/build-deb.sh BIN [OUT]}
out=${2:-bin/servanago_0.6.0_$(dpkg --print-architecture).deb}
[[ $bin = /* ]] || bin="$PWD/$bin"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/lib/systemd/system" "$stage/etc/servanago"
cp "$bin" "$stage/usr/bin/servanago"
chmod 755 "$stage/usr/bin/servanago"
cp packaging/servanago.service "$stage/lib/systemd/system/"
cp packaging/servanago-helper.service "$stage/lib/systemd/system/"
cp packaging/servanago.env "$stage/etc/servanago/servanago.env"
chmod 640 "$stage/etc/servanago/servanago.env"
sed "s/@ARCH@/$(dpkg --print-architecture)/" packaging/DEBIAN/control > "$stage/DEBIAN/control"
for s in conffiles postinst prerm postrm; do
    cp "packaging/DEBIAN/$s" "$stage/DEBIAN/$s"
    chmod 755 "$stage/DEBIAN/$s"
done

[[ $out = /* ]] || out="$PWD/$out"
dpkg-deb --root-owner-group --build "$stage" "$out"