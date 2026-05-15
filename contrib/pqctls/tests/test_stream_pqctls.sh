#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <nginx-bin> <pqctls-build-dir>" >&2
    exit 2
fi

NGINX_BIN=$1
PQCTLS_BUILD_DIR=$2
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
STREAM_PORT=9443
STREAM_PROXY_PORT=9444
UPSTREAM_PORT=6010
PP_UPSTREAM_PORT=6011

UPSTREAM_PID=
PP_UPSTREAM_PID=
NGINX_STARTED=

cleanup() {
    if [[ -n "${NGINX_STARTED}" ]]; then
        LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$NGINX_BIN" -p "$NGINX_PREFIX" -c conf/nginx.conf -s quit >/dev/null 2>&1 || true
    fi
    [[ -n "${UPSTREAM_PID}" ]] && kill "${UPSTREAM_PID}" >/dev/null 2>&1 || true
    [[ -n "${PP_UPSTREAM_PID}" ]] && kill "${PP_UPSTREAM_PID}" >/dev/null 2>&1 || true
    wait "${UPSTREAM_PID:-}" >/dev/null 2>&1 || true
    wait "${PP_UPSTREAM_PID:-}" >/dev/null 2>&1 || true
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

stream {
    server {
        listen ${STREAM_PORT} pqctls;

        pqctls_certificate         ${CERT_DIR}/server_cert.bin;
        pqctls_certificate_key     ${CERT_DIR}/server_sk.bin;
        pqctls_client_certificate  ${CERT_DIR}/root_cert.bin;
        pqctls_algorithm           ecdsa_kyber;
        pqctls_handshake_timeout   30s;

        proxy_pass 127.0.0.1:${UPSTREAM_PORT};
    }

    server {
        listen ${STREAM_PROXY_PORT} pqctls proxy_protocol;

        pqctls_certificate         ${CERT_DIR}/server_cert.bin;
        pqctls_certificate_key     ${CERT_DIR}/server_sk.bin;
        pqctls_client_certificate  ${CERT_DIR}/root_cert.bin;
        pqctls_algorithm           ecdsa_kyber;
        pqctls_handshake_timeout   30s;

        set_real_ip_from           127.0.0.1;
        proxy_protocol on;
        proxy_pass 127.0.0.1:${PP_UPSTREAM_PORT};
    }
}
EOF
}

mkdir -p "$CERT_DIR"
"$BIN_DIR/gen_identity" "$CERT_DIR"

"$BIN_DIR/upstream_server" -p "$UPSTREAM_PORT" -f "$CERT_DIR" >"$WORK_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_for_port "$UPSTREAM_PORT"

python3 "$SCRIPT_DIR/stream_proxy_protocol_upstream.py" \
    --listen-port "$PP_UPSTREAM_PORT" \
    --output "$WORK_DIR/proxy_protocol_capture.txt" >"$WORK_DIR/proxy_protocol_upstream.log" 2>&1 &
PP_UPSTREAM_PID=$!
wait_for_port "$PP_UPSTREAM_PORT"

write_nginx_config
LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$NGINX_BIN" -t -p "$NGINX_PREFIX" -c conf/nginx.conf
LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$NGINX_BIN" -p "$NGINX_PREFIX" -c conf/nginx.conf
NGINX_STARTED=1
wait_for_port "$STREAM_PORT"
wait_for_port "$STREAM_PROXY_PORT"

LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$BIN_DIR/pqctls_proxy_protocol_client" \
    -h 127.0.0.1 \
    -p "$STREAM_PORT" \
    -d "$CERT_DIR" \
    -r /size/65536 \
    -o "$WORK_DIR/stream_response.txt"

grep -q "HTTP/1.1 200 OK" "$WORK_DIR/stream_response.txt"
grep -q "Content-Length: 65536" "$WORK_DIR/stream_response.txt"

LD_LIBRARY_PATH=$OPENSSL_LIB_DIR "$BIN_DIR/pqctls_proxy_protocol_client" \
    -h 127.0.0.1 \
    -p "$STREAM_PROXY_PORT" \
    -d "$CERT_DIR" \
    -r /proxy-protocol \
    -P $'PROXY TCP4 198.51.100.10 203.0.113.20 45678 9444\r\n' \
    -o "$WORK_DIR/stream_proxy_response.txt"

grep -q "HTTP/1.1 200 OK" "$WORK_DIR/stream_proxy_response.txt"
grep -q "proxy protocol ok" "$WORK_DIR/stream_proxy_response.txt"
grep -q '^PROXY TCP4 198.51.100.10 203.0.113.20 45678 9444' \
    "$WORK_DIR/proxy_protocol_capture.txt"

echo "stream pqctls smoke test passed"
