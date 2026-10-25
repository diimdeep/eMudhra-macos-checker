#!/bin/sh
# Remove the two roots the compromised intermediates chain to from the system
# PEM bundle (/etc/ssl/cert.pem), which curl, LibreSSL and the stock Python read.
#
#   sh checking/trim_bundle.sh           # back up, then remove the roots
#   sh checking/trim_bundle.sh --undo    # restore the backup and delete it
#   sh checking/trim_bundle.sh --list    # show whether the roots are present
#
# macOS may rewrite /etc/ssl/cert.pem on a system update; run it again after one.
# Set BUNDLE to trim another file.

set -eu

BUNDLE=${BUNDLE:-/etc/ssl/cert.pem}
BAK=$BUNDLE.bak
PATTERN='/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$'

present() {
    grep -Ec "^=== .*$PATTERN" "$1" || true
}

case "${1:-}" in
--list)
    echo "$BUNDLE: $(grep -c '^=== ' "$BUNDLE") roots, $(present "$BUNDLE") of the 2 targets present"
    if [ -f "$BAK" ]; then echo "$BAK: backup exists"; fi
    ;;
--undo)
    [ -f "$BAK" ] || { echo "no backup at $BAK" >&2; exit 1; }
    sudo cp "$BAK" "$BUNDLE"
    sudo rm "$BAK"
    echo "restored $BUNDLE"
    ;;
"")
    # An existing backup is the original; copying again would overwrite it with a trimmed file.
    [ -f "$BAK" ] || sudo cp "$BUNDLE" "$BAK"
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    awk -v pat="$PATTERN" '
        /^(###|===) /          { skip = 0 }
        $0 ~ "^=== .*" pat     { skip = 1 }
        !skip' "$BAK" > "$tmp"
    sudo cp "$tmp" "$BUNDLE"
    echo "removed $(( $(present "$BAK") - $(present "$BUNDLE") )) roots from $BUNDLE; backup at $BAK"
    ;;
*)
    echo "usage: $0 [--undo | --list]" >&2
    exit 2
    ;;
esac
