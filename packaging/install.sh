#!/bin/bash
# Install ServanaGo from this checkout: build the deb, install it with apt.
# Root only; host setup beyond the deb (user, dirs, unit) lives in the package's postinst.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo packaging/install.sh)" >&2
    exit 1
fi
cd "$(dirname "$0")/.."

make build
packaging/build-deb.sh bin/servanago
apt-get install ./bin/servanago_0.16.1_*.deb

echo "Edit /etc/servanago/servanago.env, then: systemctl start servanago"