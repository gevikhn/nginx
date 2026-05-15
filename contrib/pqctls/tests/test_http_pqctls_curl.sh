#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <nginx-bin> <pqctls-build-dir> [curl-bin]" >&2
    exit 2
fi

NGINX_BIN=$1
PQCTLS_BUILD_DIR=$2
CURL_BIN=${3:-/home/midraos/projects/curl/build-pqctls/src/curl}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BIN_DIR="$PQCTLS_BUILD_DIR/bin"
OPENSSL_PREFIX=${OPENSSL_ROOT_DIR:-/home/midraos/Tongsuo/Tongsuo-8.5.0-pre1/_install}
OPENSSL_LIB_DIR=$OPENSSL_PREFIX/lib64
if [[ ! -d "$OPENSSL_LIB_DIR" ]]; then
    OPENSSL_LIB_DIR=$OPENSSL_PREFIX/lib
fi

WORK_DIR=$(mktemp -d)
CERT_DIR="$WORK_DIR/certs"
NGINX_PREFIX="$WORK_DIR/nginx"
HTTP_PORT=9443
UPSTREAM_PORT=6020
DOWNLOAD_SIZE=32768

UPSTREAM_PID=
NGINX_STARTED=
MULTISSL=

cleanup() {
    if [[ -n "${NGINX_STARTED}" ]]; then
        LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$NGINX_BIN" -p "$NGINX_PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
    fi
    [[ -n "${UPSTREAM_PID}" ]] && kill "${UPSTREAM_PID}" >/dev/null 2>&1 || true
    wait "${UPSTREAM_PID:-}" >/dev/null 2>&1 || true
    if [[ -z "${KEEP_WORK_DIR:-}" ]]; then
        rm -rf "$WORK_DIR"
    else
        echo "Keeping work directory: $WORK_DIR" >&2
    fi
}

trap cleanup EXIT

wait_for_port() {
    local port=$1
    local attempts=50

    while (( attempts > 0 )); do
        if python3 - "$port" <<'PY'
import sys

port = int(sys.argv[1])
port_hex = f"{port:04X}"

def is_listening(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local_address = fields[1]
                state = fields[3]
                if state != "0A":
                    continue
                _, local_port = local_address.split(":")
                if local_port.upper() == port_hex:
                    return True
    except FileNotFoundError:
        return False
    return False

raise SystemExit(0 if is_listening("/proc/net/tcp") or is_listening("/proc/net/tcp6") else 1)
PY
        then
            return 0
        fi
        sleep 0.1
        attempts=$((attempts - 1))
    done

    echo "Timed out waiting for port ${port}" >&2
    return 1
}

write_nginx_config() {
    mkdir -p "$NGINX_PREFIX/conf" "$NGINX_PREFIX/logs"
    cat >"$NGINX_PREFIX/conf/nginx.conf" <<EOF
worker_processes  1;
error_log logs/error.log info;
pid logs/nginx.pid;

events {
    worker_connections 1024;
}

http {
    access_log logs/access.log;

    server {
        listen ${HTTP_PORT} pqctls;

        pqctls_certificate         ${CERT_DIR}/server_cert.bin;
        pqctls_certificate_key     ${CERT_DIR}/server_sk.bin;
        pqctls_client_certificate  ${CERT_DIR}/root_cert.bin;
        pqctls_algorithm           ecdsa_kyber;
        pqctls_handshake_timeout   30s;

        location / {
            proxy_pass http://127.0.0.1:${UPSTREAM_PORT};
        }
    }
}
EOF
}

run_nginx() {
    LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$NGINX_BIN" "$@"
}

run_curl() {
    local -a cmd=(
        "$CURL_BIN"
        --noproxy '*'
        --cacert "$CERT_DIR/root_cert.bin"
        --cert "$CERT_DIR/client_cert.bin"
        --key "$CERT_DIR/client_sk.bin"
        -sS
        -D "$WORK_DIR/curl.headers"
        -o "$WORK_DIR/curl.body"
        -w 'code=%{http_code} size=%{size_download}\n'
        "https://127.0.0.1:${HTTP_PORT}/size/${DOWNLOAD_SIZE}"
    )

    if [[ -n "${MULTISSL}" ]]; then
        CURL_SSL_BACKEND=pqctls LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "${cmd[@]}"
    else
        LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "${cmd[@]}"
    fi
}

if [[ ! -x "$CURL_BIN" ]]; then
    echo "curl binary not found: $CURL_BIN" >&2
    exit 1
fi

VERSION_OUTPUT=$(LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$CURL_BIN" --version)
grep -q 'pqctls/' <<<"$VERSION_OUTPUT"
if grep -q 'MultiSSL' <<<"$VERSION_OUTPUT"; then
    MULTISSL=1
fi

mkdir -p "$CERT_DIR"
"$BIN_DIR/gen_identity" "$CERT_DIR"

"$BIN_DIR/upstream_server" -p "$UPSTREAM_PORT" -f "$CERT_DIR" >"$WORK_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_for_port "$UPSTREAM_PORT"

write_nginx_config
run_nginx -t -p "$NGINX_PREFIX" -c conf/nginx.conf
run_nginx -p "$NGINX_PREFIX" -c conf/nginx.conf
NGINX_STARTED=1
wait_for_port "$HTTP_PORT"

RESULT=$(run_curl)
echo "$RESULT" >"$WORK_DIR/curl.result"
tr -d '\r' <"$WORK_DIR/curl.headers" >"$WORK_DIR/curl.headers.norm"

grep -q '^code=200 size='"$DOWNLOAD_SIZE"'$' "$WORK_DIR/curl.result"
grep -q '^HTTP/1.1 200 OK' "$WORK_DIR/curl.headers.norm"
grep -qi '^Content-Length: '"$DOWNLOAD_SIZE"'$' "$WORK_DIR/curl.headers.norm"
test "$(wc -c <"$WORK_DIR/curl.body")" -eq "$DOWNLOAD_SIZE"
grep -q "\"GET /size/${DOWNLOAD_SIZE} HTTP/1.1\" 200 ${DOWNLOAD_SIZE} " \
    "$NGINX_PREFIX/logs/access.log"

echo "http pqctls curl smoke test passed"
