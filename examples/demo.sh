#!/usr/bin/env bash
# Real cross-language data exchange over the Blind Dead Drop.
#
# Each "worker" waits for a request, PROCESSES it (uppercases the text, standing
# in for real work), and posts a response — a blind RPC. The requester and the
# worker are written in different languages and only share the 32-byte secret;
# the server never sees plaintext and cannot link the two.
#
# Needs only a local `php` — no database. The server writes blobs to a temp dir.
# Run from the repo root:  bash examples/demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Throwaway storage for the demo server (cleaned up on exit).
export BDDPHP_DATA_DIR="${BDDPHP_DATA_DIR:-$(mktemp -d)}"

PORT="${PORT:-18491}"
PY="python3 examples/python/example.py"
CPP="examples/cpp/example"
PHP_BIN="$(command -v php || true)"
C="--port $PORT --scheme http"

cleanup() {
    [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null || true
    [[ -n "${BDDPHP_DATA_DIR:-}" ]] && rm -rf "$BDDPHP_DATA_DIR" || true
}
trap cleanup EXIT

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# ---- setup -------------------------------------------------------------
say "Setup"
echo "preparing storage directory..."
bin/bdd migrate
echo "building C++ example..."
( cd examples/cpp && make example >/dev/null )
export BDD_SECRET="$(bin/bdd keygen)"
echo "shared secret: ${BDD_SECRET:0:16}… (known only to the two parties)"

PHP_CLI_SERVER_WORKERS=8 php -S "127.0.0.1:$PORT" public/index.php >/dev/null 2>&1 &
SRV=$!
sleep 1.2

# ---- exchange 1: Python requester  ->  C++ worker ----------------------
say "Exchange 1 — Python asks, C++ processes (channel 1)"
$CPP $C reply-upper 1 >/dev/null 2>&1 &   # C++ worker waits for the request
WORKER=$!
sleep 0.4
echo "  Python -> request : 'hello from python'"
$PY $C send-request 1 "hello from python" >/dev/null 2>&1
echo "  Python <- response: '$($PY $C wait-response 1 2>/dev/null)'  (computed by C++)"
wait "$WORKER"

# ---- exchange 2: C++ requester  ->  Python worker ----------------------
say "Exchange 2 — C++ asks, Python processes (channel 2)"
$PY $C reply-upper 2 >/dev/null 2>&1 &    # Python worker waits for the request
WORKER=$!
sleep 0.4
echo "  C++ -> request : 'hello from c++'"
$CPP $C send-request 2 "hello from c++" >/dev/null 2>&1
echo "  C++ <- response: '$($CPP $C wait-response 2 2>/dev/null)'  (computed by Python)"
wait "$WORKER"

# ---- exchange 3: PHP requester  ->  Python worker ----------------------
say "Exchange 3 — PHP (native package) asks, Python processes (channel 3)"
if [[ -n "$PHP_BIN" ]]; then
    $PY $C reply-upper 3 >/dev/null 2>&1 &
    WORKER=$!
    sleep 0.4
    echo "  PHP -> request : 'hello from php'"
    php examples/php/example.php $C send-request 3 "hello from php" >/dev/null 2>&1
    echo "  PHP <- response: '$(php examples/php/example.php $C wait-response 3 2>/dev/null)'  (computed by Python)"
    wait "$WORKER"
else
    echo "SKIPPED: no 'php' runtime found on this machine."
fi

say "Done — three blind RPCs across languages, server never saw plaintext."
