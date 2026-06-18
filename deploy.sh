#!/usr/bin/env bash
# Deploy bddphp to the shared host over FTP.
#
# Reads credentials from ~/.env (the "BDD PHP" section): FTP_HOST_BDD,
# FTP_USER_BDD, FTP_PASS_BDD and the MYSQL_*_BDD database settings. Nothing
# secret is stored in the repo.
#
# It stages the public_html layout (front controller + .htaccess + src/, plus a
# generated .env carrying the DB settings) and mirrors it to the host. The
# server is plain PHP behind the host's web server; message content is already
# end-to-end encrypted, so HTTPS is provided by the host, not the app.
#
#   ./deploy.sh            # build staging and upload
#   ./deploy.sh --dry-run  # build staging only, print the tree, upload nothing
set -euo pipefail

ENV_FILE="${BDD_ENV_FILE:-$HOME/.env}"
# Standard Hostinger plans serve from public_html. The *.hostingersite.com
# preview domain used here serves from the FTP landing directory itself (it holds
# default.php), so deploy with BDD_REMOTE_DIR=. for that target.
REMOTE_DIR="${BDD_REMOTE_DIR:-public_html}"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

[[ -f "$ENV_FILE" ]] || { echo "error: $ENV_FILE not found" >&2; exit 1; }

# Pull just the keys we need from the env file (no `source`, values have specials).
get() { grep -E "^$1=" "$ENV_FILE" | head -n1 | cut -d= -f2-; }
FTP_HOST="$(get FTP_HOST_BDD)"
FTP_USER="$(get FTP_USER_BDD)"
FTP_PASS="$(get FTP_PASS_BDD)"
MYSQL_HOST="$(get MYSQL_HOST_BDD)"
MYSQL_DATA="$(get MYSQL_DATA_BDD)"
MYSQL_USER="$(get MYSQL_USER_BDD)"
MYSQL_PASS="$(get MYSQL_PASS_BDD)"

FTP_HOST="${FTP_HOST#ftp://}"
[[ -n "$FTP_HOST" && -n "$FTP_USER" && -n "$FTP_PASS" ]] \
    || { echo "error: missing FTP_*_BDD in $ENV_FILE" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# public_html layout: front controller + .htaccess at root, src/ beside them.
# docs/index.html becomes the static landing page (served by DirectoryIndex).
cp "$ROOT/public/index.php" "$STAGE/index.php"
cp "$ROOT/public/.htaccess" "$STAGE/.htaccess"
cp "$ROOT/docs/index.html" "$STAGE/index.html"
cp -r "$ROOT/src" "$STAGE/src"
# Downloadable examples bundle, linked from the docs page. Built fresh from
# examples/ + src/ (the PHP example imports the package), minus build artifacts.
if command -v zip >/dev/null; then
    ( cd "$ROOT" && rm -f docs/bddphp-examples.zip \
        && zip -r -q docs/bddphp-examples.zip examples src \
            -x 'examples/cpp/example' 'examples/cpp/selftest' \
               'examples/python/__pycache__/*' )
    cp "$ROOT/docs/bddphp-examples.zip" "$STAGE/bddphp-examples.zip"
elif [[ -f "$ROOT/docs/bddphp-examples.zip" ]]; then
    cp "$ROOT/docs/bddphp-examples.zip" "$STAGE/bddphp-examples.zip"
else
    echo "warning: zip not found and no prebuilt bundle — skipping examples .zip" >&2
fi

# Generated production .env (denied by .htaccess). Charset utf8mb4 for the host.
cat > "$STAGE/.env" <<EOF
MYSQL_HOST_BDD=$MYSQL_HOST
MYSQL_DATA_BDD=$MYSQL_DATA
MYSQL_USER_BDD=$MYSQL_USER
MYSQL_PASS_BDD=$MYSQL_PASS
BDDPHP_DB_CHARSET=utf8mb4
EOF
chmod 600 "$STAGE/.env"

echo "staged deploy tree:" >&2
( cd "$STAGE" && find . -type f | sort | sed 's/^/  /' ) >&2

if [[ "$DRY_RUN" == 1 ]]; then
    echo "dry run: nothing uploaded. Remote dir would be: $REMOTE_DIR" >&2
    exit 0
fi

echo "uploading to ftp://$FTP_HOST/$REMOTE_DIR as $FTP_USER ..." >&2

if command -v lftp >/dev/null; then
    lftp -u "$FTP_USER,$FTP_PASS" "$FTP_HOST" <<EOF
set ftp:ssl-allow true
set ssl:verify-certificate no
mkdir -p $REMOTE_DIR
mirror --reverse --delete --verbose \
    --exclude tests/ --exclude vendor/ \
    "$STAGE/" "$REMOTE_DIR/"
bye
EOF
elif command -v curl >/dev/null; then
    # No lftp: upload each staged file with curl, creating remote dirs as needed.
    # Opportunistic FTPS (--ssl), cert verification relaxed like the lftp path.
    ( cd "$STAGE" && find . -type f | sed 's#^\./##' ) | while read -r rel; do
        echo "  -> $REMOTE_DIR/$rel" >&2
        curl -sS --ssl -k --ftp-create-dirs \
            -u "$FTP_USER:$FTP_PASS" \
            -T "$STAGE/$rel" \
            "ftp://$FTP_HOST/$REMOTE_DIR/$rel"
    done
else
    echo "error: need lftp or curl to upload" >&2; exit 1
fi
echo "done." >&2
