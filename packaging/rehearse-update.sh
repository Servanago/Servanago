#!/bin/bash
# Rehearse the self-upgrade and its rollback with real dpkg and systemctl on a SCRATCH host (a VM or a throwaway
# machine, never a real install). Two halves in one file:
#
#   packaging/rehearse-update.sh build OUTDIR      on the dev machine, no root. Builds fake releases 0.90.0-0.94.0,
#                                                  signs their manifests with the real release key, and writes a
#                                                  bundle (the debs laid out like GitHub, a TLS file server, a
#                                                  throwaway certificate and this script).
#   REHEARSAL_SCRATCH=yes ./rehearse-update.sh host setup|A|B|C|D|E|all|cleanup    on the scratch host, as root,
#                                                  from inside the copied bundle.
#
# The host half points github.com at a local TLS server (an /etc/hosts line and a CA in the system store), so the
# real, unmodified binaries fetch their manifests and packages from the bundle. `cleanup` undoes all of it.
#
# Scenarios (the host starts at 0.90.0):
#   A  0.90.0 -> 0.91.0  good upgrade
#   B  0.91.0 -> 0.92.0  new binary exits at once: health fails, rollback restores 0.91.0
#   C  0.91.0 -> 0.93.0  postinst fails: dpkg install fails, rollback restores 0.91.0
#   D  0.91.0 -> 0.94.0  new binary exits AND the old package's postinst fails: rollback fails, units stay stopped,
#                        NEEDS_HANDS.txt is written; the script then runs its commands to prove they recover
#   E  latest.json altered after signing: refused, nothing changes
set -euo pipefail

VERSIONS="0.90.0 0.91.0 0.92.0 0.93.0 0.94.0"
REL=Servanago/Servanago/releases
PORT_UI=18081
FLAG=/var/lib/servanago-rehearsal-fail-postinst
STAMP=/var/lib/servanago-rehearsal.stamp
CA=/usr/local/share/ca-certificates/servanago-rehearsal.crt
WWW_UNIT=servanago-rehearsal-www

die() { echo "rehearse-update: $*" >&2; exit 1; }

# ---------------------------------------------------------------- build (dev machine)

# repack DEB VERSION FIRST_LINES: rewrite a package's version and, when FIRST_LINES is not empty, put those
# lines at the top of its postinst. Uses a scratch directory, never the repo.
repack() {
    local deb=$1 v=$2 extra=$3 d
    d=$(mktemp -d)
    dpkg-deb -R "$deb" "$d/x"
    { printf 'Version: %s\n' "$v"; grep -v '^Version:' "$d/x/DEBIAN/control"; } > "$d/control"
    cat "$d/control" > "$d/x/DEBIAN/control"
    if [ -n "$extra" ]; then
        { head -n1 "$d/x/DEBIAN/postinst"; printf '%s\n' "$extra"; tail -n +2 "$d/x/DEBIAN/postinst"; } > "$d/postinst"
        cat "$d/postinst" > "$d/x/DEBIAN/postinst"
    fi
    dpkg-deb --root-owner-group --build "$d/x" "$deb" >/dev/null
    rm -rf "$d"
}

build() {
    local out=${1:?usage: rehearse-update.sh build OUTDIR} key=${KEYFILE:-$HOME/.config/servanago/release.key}
    local repo arch work www v bin deb
    repo=$(cd "$(dirname "$0")/.." && pwd)
    [ -e "$out" ] && die "$out exists; give a new directory (nothing is overwritten)"
    [ -r "$key" ] || die "release key $key not readable (KEYFILE=... to point elsewhere)"
    for t in go dpkg-deb openssl; do command -v "$t" >/dev/null || die "$t is needed"; done
    arch=$(dpkg --print-architecture)
    mkdir -p "$out"; out=$(cd "$out" && pwd)
    work=$(mktemp -d); trap "rm -rf '$work'" EXIT
    www=$out/www/$REL
    cd "$repo"

    for v in $VERSIONS; do
        mkdir -p "$www/download/v$v"
        deb=$www/download/v$v/servanago_${v}_$arch.deb
        case $v in
        0.92.0 | 0.94.0) # a binary that exits at once: the package installs, the panel never comes up
            printf '#!/bin/sh\nexit 1\n' > "$work/bin-$v" ;;
        *)
            CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/servanago/servanago/internal/buildinfo.Version=$v" \
                -o "$work/bin-$v" ./cmd/servanago ;;
        esac
        chmod 755 "$work/bin-$v"
        packaging/build-deb.sh "$work/bin-$v" "$deb" >/dev/null
        case $v in
        0.91.0) # the package a rollback goes back to: fails its postinst while the flag file exists (scenario D)
            repack "$deb" "$v" "[ -e $FLAG ] && { echo 'rehearsal: forced postinst failure' >&2; exit 1; }" ;;
        0.93.0) repack "$deb" "$v" "echo 'rehearsal: postinst always fails' >&2; exit 1" ;;
        *) repack "$deb" "$v" "" ;;
        esac
        "$work/bin-0.90.0" manifest build --deb "$deb" --notes "https://github.com/Servanago/Servanago/releases/tag/v$v" \
            > "$www/download/v$v/latest.json"
        "$work/bin-0.90.0" manifest sign "$key" "$www/download/v$v/latest.json"
    done

    # a small TLS file server standing in for github.com
    mkdir "$work/serve"
    cat > "$work/serve/main.go" <<'EOF'
package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	dir := flag.String("dir", "", "")
	cert := flag.String("cert", "", "")
	key := flag.String("key", "", "")
	addr := flag.String("addr", "127.0.0.1:443", "")
	flag.Parse()
	log.Fatal(http.ListenAndServeTLS(*addr, *cert, *key, http.FileServer(http.Dir(*dir))))
}
EOF
    (cd "$work/serve" && go mod init rehearsal >/dev/null 2>&1 && CGO_ENABLED=0 go build -o "$out/serve" .)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
        -keyout "$out/key.pem" -out "$out/cert.pem" -subj /CN=github.com -addext subjectAltName=DNS:github.com 2>/dev/null
    chmod 600 "$out/key.pem"
    echo "$arch" > "$out/arch"
    cp "$repo/packaging/rehearse-update.sh" "$out/rehearse-update.sh"
    chmod 755 "$out/rehearse-update.sh"
    echo "bundle in $out ($arch)"
    echo "copy it to the scratch host, then there: sudo REHEARSAL_SCRATCH=yes ./rehearse-update.sh host all"
}

# ---------------------------------------------------------------- host (scratch machine)

HERE=$(cd "$(dirname "$0")" && pwd)
WWW=$HERE/www/$REL
LATEST=$WWW/latest/download
FAILS=0

ver() { dpkg-query -W -f='${Version}' servanago 2>/dev/null || echo none; }
active() { systemctl is-active --quiet servanago.service && systemctl is-active --quiet servanago-helper.service; }
login_ok() { curl -fsS -o /dev/null "http://127.0.0.1:$PORT_UI/login" 2>/dev/null; }
wait_login() { local i; for i in $(seq 1 90); do login_ok && return 0; sleep 1; done; return 1; }

check() { # check DESCRIPTION CONDITION-COMMAND...
    local what=$1; shift
    if "$@"; then echo "    ok    $what"; else echo "    FAIL  $what"; FAILS=$((FAILS + 1)); fi
}

setup() {
    [ "$(id -u)" = 0 ] || die "run as root"
    [ "${REHEARSAL_SCRATCH:-}" = yes ] || die "this changes /etc/hosts, the system CA store and installs a package: set REHEARSAL_SCRATCH=yes on a scratch host only"
    [ -d /run/systemd/system ] || die "systemd is not running here"
    [ ! -e "$STAMP" ] || die "already set up (run cleanup first)"
    if dpkg -s servanago 2>/dev/null | grep -q '^Status: .* installed'; then die "servanago is installed here: this is not a scratch host"; fi
    for p in /etc/servanago /var/lib/servanago /var/lib/servanago-update /var/log/servanago; do
        [ ! -e "$p" ] || die "$p exists: this is not a scratch host"
    done
    listening=$(ss -ltn)
    if grep -qE '[:.]443 ' <<<"$listening"; then die "port 443 is in use; the fake github needs it"; fi
    [ "$(cat "$HERE/arch")" = "$(dpkg --print-architecture)" ] || die "bundle is for $(cat "$HERE/arch"), this host is $(dpkg --print-architecture)"
    for t in curl systemd-run update-ca-certificates; do command -v "$t" >/dev/null || die "$t is needed"; done

    echo "== trust the throwaway certificate, point github.com at this host"
    touch "$STAMP"
    install -m 644 "$HERE/cert.pem" "$CA"
    update-ca-certificates >/dev/null
    echo "127.0.0.1 github.com # servanago-rehearsal" >> /etc/hosts
    systemd-run --quiet --unit="$WWW_UNIT" "$HERE/serve" -dir "$HERE/www" -cert "$HERE/cert.pem" -key "$HERE/key.pem"
    local i; for i in $(seq 1 20); do
        curl -fsS -o /dev/null "https://github.com/$REL/download/v0.90.0/latest.json" 2>/dev/null && break
        sleep 1
    done
    curl -fsS -o /dev/null "https://github.com/$REL/download/v0.90.0/latest.json" || die "the fake github does not answer"

    echo "== install 0.90.0 from the bundle (this is the hand-installed first release)"
    dpkg -i "$WWW/download/v0.90.0/servanago_0.90.0_$(dpkg --print-architecture).deb" >/dev/null
    cat >> /etc/servanago/servanago.env <<EOF
# servanago-rehearsal
SERVANAGO_HOST=rehearsal.example.test
ACME_EMAIL=rehearsal@example.test
ACME_ISSUER=internal
HTTP_PORT=18080
HTTPS_PORT=18443
UI_LISTEN=127.0.0.1:$PORT_UI
EOF
    systemctl start servanago-helper.service servanago.service
    wait_login || { journalctl -u servanago -n 30 --no-pager >&2; die "0.90.0 did not come up"; }
    echo "installed $(ver), panel answers on 127.0.0.1:$PORT_UI"
}

publish() { # publish VERSION: make that release the "latest"
    mkdir -p "$LATEST"
    cp "$WWW/download/v$1/latest.json" "$LATEST/latest.json"
    cp "$WWW/download/v$1/latest.json.sig" "$LATEST/latest.json.sig"
}

upgrade() { # sets OUT and RC
    set +e
    OUT=$(/usr/bin/servanago update --yes 2>&1)
    RC=$?
    set -e
    echo "$OUT" | sed 's/^/    | /'
}

scenario() {
    [ -e "$STAMP" ] || die "run setup first"
    local s=$1 want
    echo "== scenario $s"
    case $s in
    A)
        check "starts at 0.90.0" test "$(ver)" = 0.90.0
        publish 0.91.0; upgrade
        check "update exits 0" test "$RC" = 0
        check "reports the upgrade" grep -q 'upgraded 0.90.0 to 0.91.0' <<<"$OUT"
        check "0.91.0 installed" test "$(ver)" = 0.91.0
        check "both units active" active
        check "panel answers" wait_login
        check "the database copy was made" test -e /var/lib/servanago/servanago.db.pre-0.90.0
        check "env file kept (conffile)" grep -q servanago-rehearsal /etc/servanago/servanago.env
        ;;
    B | C)
        want=0.92.0; [ "$s" = C ] && want=0.93.0
        check "starts at 0.91.0" test "$(ver)" = 0.91.0
        publish "$want"; upgrade
        check "update fails" test "$RC" != 0
        check "says the old version was put back" grep -q 'was put back' <<<"$OUT"
        check "0.91.0 installed again" test "$(ver)" = 0.91.0
        check "package is fully configured" bash -c "dpkg -s servanago | grep -q '^Status: install ok installed'"
        check "both units active" active
        check "panel answers" wait_login
        check "the database copy was made" bash -c 'ls /var/lib/servanago/servanago.db.pre-0.91.0* >/dev/null'
        ;;
    D)
        check "starts at 0.91.0" test "$(ver)" = 0.91.0
        touch "$FLAG"
        publish 0.94.0; upgrade
        check "update fails" test "$RC" != 0
        check "says the rollback failed too" grep -q 'so did the rollback' <<<"$OUT"
        check "NEEDS_HANDS.txt written" test -s /var/lib/servanago-update/NEEDS_HANDS.txt
        check "services left stopped" bash -c '! systemctl is-active --quiet servanago.service'
        echo "    -- running the commands from NEEDS_HANDS.txt"
        rm -f "$FLAG"
        local line
        while IFS= read -r line; do
            [ -n "$line" ] && echo "    \$ $line" && bash -c "$line" 2>&1 | sed 's/^/      /'
        done < <(tail -n +$(($(grep -n '^$' /var/lib/servanago-update/NEEDS_HANDS.txt | head -n1 | cut -d: -f1) + 1)) /var/lib/servanago-update/NEEDS_HANDS.txt)
        check "recovered to 0.91.0" test "$(ver)" = 0.91.0
        check "both units active" active
        check "panel answers" wait_login
        ;;
    E)
        check "starts at 0.91.0" test "$(ver)" = 0.91.0
        publish 0.92.0
        printf '\n' >> "$LATEST/latest.json" # the signature no longer matches these bytes
        upgrade
        check "update fails" test "$RC" != 0
        check "names the signature" grep -q 'does not match a trusted key' <<<"$OUT"
        check "still 0.91.0" test "$(ver)" = 0.91.0
        check "both units active" active
        ;;
    *) die "unknown scenario $s" ;;
    esac
}

cleanup() {
    [ "$(id -u)" = 0 ] || die "run as root"
    [ -e "$STAMP" ] || die "no rehearsal to clean up (no $STAMP)"
    systemctl stop servanago.service servanago-helper.service servanago-upgrade.service 2>/dev/null || true
    dpkg --purge servanago >/dev/null 2>&1 || true
    rm -rf /var/lib/servanago /var/lib/servanago-update /var/lib/servanago-build /var/log/servanago /etc/servanago
    rm -f /etc/systemd/system/servanago-upgrade.service "$FLAG"
    systemctl daemon-reload
    systemctl stop "$WWW_UNIT" 2>/dev/null || true
    grep -v '# servanago-rehearsal$' /etc/hosts > "$HERE/.hosts.new" || true
    cat "$HERE/.hosts.new" > /etc/hosts; rm -f "$HERE/.hosts.new"
    rm -f "$CA"; update-ca-certificates --fresh >/dev/null
    rm -f "$STAMP"
    echo "cleaned up"
}

host() {
    case ${1:-} in
    setup) setup ;;
    A | B | C | D | E) scenario "$1" ;;
    all)
        setup
        for s in A B C D E; do scenario "$s"; done
        if [ "$FAILS" = 0 ]; then echo "== all scenarios passed"; else echo "== $FAILS check(s) FAILED"; exit 1; fi
        echo "the host is left as is for inspection; run: ./rehearse-update.sh host cleanup"
        ;;
    cleanup) cleanup ;;
    *) die "usage: host setup|A|B|C|D|E|all|cleanup" ;;
    esac
    if [ "$FAILS" != 0 ]; then exit 1; fi
}

case ${1:-} in
build) shift; build "$@" ;;
host) shift; host "$@" ;;
*) die "usage: rehearse-update.sh build OUTDIR | host setup|A|B|C|D|E|all|cleanup" ;;
esac
