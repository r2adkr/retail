#!/bin/sh
# Installs retail on Linux or macOS from the newest release, nothing to set up:
#
#   curl -fsSL https://raw.githubusercontent.com/r2adkr/retail/main/scripts/install.sh | sh
#   ... | sh -s -- --invite retail1...   and join a network
#   ... | sh -s -- --server              and host a network here (prints an invite)
#
# Debian and Ubuntu get the release's .deb through apt; other Linux systems
# get the installer taken out of it; macOS gets the one in the disk image.
# Every download is checked against the release's SHA256SUMS.
# RETAIL_RELEASES points elsewhere (a mirror, or file:// for tests).
set -eu

INVITE=""
SERVER=0
while [ $# -gt 0 ]; do
    case "$1" in
        --invite) INVITE=${2:?--invite needs a code}; shift 2 ;;
        --invite=*) INVITE=${1#--invite=}; shift ;;
        --server) SERVER=1; shift ;;
        -h|--help) sed -n '2,12p' "$0" 2>/dev/null || true; exit 0 ;;
        *) echo "retail: unknown option $1" >&2; exit 2 ;;
    esac
done

BASE=${RETAIL_RELEASES:-https://github.com/r2adkr/retail/releases/latest/download}
say() { printf 'retail: %s\n' "$*"; }
die() { printf 'retail: %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run this as root (sudo was not found)"
    SUDO=sudo
fi

case "$(uname -s)" in
    Linux)
        case "$(uname -m)" in
            x86_64|amd64) ASSET=retail-linux-x86_64.deb ;;
            aarch64|arm64) ASSET=retail-linux-aarch64.deb ;;
            armv7l|armv7*|armv6l) ASSET=retail-linux-arm.deb ;;
            *) die "no release for $(uname -m)" ;;
        esac ;;
    Darwin) ASSET=retail-macos.dmg ;;
    *) die "this script is for Linux and macOS; on Windows run retail-windows-x86_64.exe" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {  # url file
    if command -v curl >/dev/null 2>&1; then
        # HTTPS only, redirects too (file: for a local mirror)
        curl -fsSL --proto '=https,file' --proto-redir '=https' -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "curl or wget is needed"
    fi
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

say "downloading $ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "cannot reach $BASE"
fetch "$BASE/$ASSET" "$TMP/$ASSET" || die "cannot download $ASSET"
want=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")
[ -n "$want" ] || die "the release lists no $ASSET"
[ "$(sha256 "$TMP/$ASSET")" = "$want" ] || die "$ASSET does not match the release's checksum"

# The offset and size of member $2 of the ar archive $1 (a .deb)
ar_member() {
    off=8
    total=$(wc -c <"$1")
    while [ "$off" -lt "$total" ]; do
        name=$(dd if="$1" bs=1 skip="$off" count=16 2>/dev/null | tr -d ' /')
        size=$(dd if="$1" bs=1 skip=$((off + 48)) count=10 2>/dev/null | tr -d ' ')
        if [ "$name" = "$2" ]; then
            echo "$((off + 60)) $size"
            return 0
        fi
        off=$((off + 60 + size + size % 2))
    done
    return 1
}

# The installer joins with the invite itself; through apt it is installed first
JOINED=0
case "$ASSET" in
    *.deb)
        if command -v apt-get >/dev/null 2>&1 && [ -z "${RETAIL_NO_APT:-}" ]; then
            say "installing the package"
            cp "$TMP/$ASSET" "$TMP/retail.deb"
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$TMP/retail.deb" >/dev/null
        else
            member=$(ar_member "$TMP/$ASSET" data.tar) || die "$ASSET is not a retail package"
            set -- $member
            tail -c +"$(($1 + 1))" "$TMP/$ASSET" | head -c "$2" | tar -xO ./usr/lib/retail/retail-installer >"$TMP/installer"
            chmod 755 "$TMP/installer"
            say "installing"
            if [ -n "$INVITE" ]; then
                $SUDO "$TMP/installer" --yes --invite "$INVITE"
                JOINED=1
            else
                $SUDO "$TMP/installer" --yes
            fi
        fi ;;
    *.dmg)
        hdiutil attach -nobrowse -readonly -mountpoint "$TMP/vol" "$TMP/$ASSET" >/dev/null
        say "installing"
        if [ -n "$INVITE" ]; then
            $SUDO "$TMP/vol/retail.app/Contents/MacOS/retail" --yes --invite "$INVITE" || { hdiutil detach "$TMP/vol" >/dev/null; exit 1; }
            JOINED=1
        else
            $SUDO "$TMP/vol/retail.app/Contents/MacOS/retail" --yes || { hdiutil detach "$TMP/vol" >/dev/null; exit 1; }
        fi
        hdiutil detach "$TMP/vol" >/dev/null ;;
esac

# Where the installer put the programs
BIN=/usr/local/bin
[ "$(uname -s)" = Darwin ] && BIN=/Library/retail/bin
if [ -n "$INVITE" ] && [ "$JOINED" = 0 ]; then
    say "joining"
    $SUDO "$BIN/retail" up --invite "$INVITE"
fi
if [ "$SERVER" = 1 ]; then
    # Starts a server that does not join itself and prints the first invite
    $SUDO "$BIN/retaild" install --server
fi
if [ -z "$INVITE" ] && [ "$SERVER" = 0 ]; then
    say "installed. Join a network with: retail up --invite <code>   or host one with: sudo retaild install --server"
fi
