# NGINX `pqctls` Version Migration Guide

This document describes how to move the `pqctls` NGINX core patch stack from
one upstream release tag to a newer one.

The workflow assumes:

- Upstream NGINX is tracked in this repository.
- PQCTLS HTTP/stream addon modules and smoke tests remain in the PQCTLS
  repository.
- Core changes are maintained only as Git commits in this repository, not as a
  standalone `.patch` file in PQCTLS.

## Branch Layout

- Upstream base: `release-<version>`
- PQCTLS maintenance branch: `pqctls/release-<version>`

Each `pqctls` branch should keep the same commit layering:

1. `core: add pqctls connection hooks`
2. `http: add pqctls listener plumbing`
3. `stream: add pqctls listener plumbing`

Keeping these as separate commits makes rebases and conflict resolution much
easier than maintaining one monolithic patch.

## Migration Procedure

Example: move from `pqctls/release-1.29.8` to `release-1.30.0`.

```bash
cd /path/to/nginx

git fetch origin --tags
git switch pqctls/release-1.29.8

git switch -c pqctls/release-1.30.0 release-1.30.0
git cherry-pick \
    <core-commit> \
    <http-commit> \
    <stream-commit>
```

You can get the source commits from the previous PQCTLS branch:

```bash
git log --oneline release-1.29.8..pqctls/release-1.29.8
```

## Conflict Resolution Rules

Resolve conflicts in commit order. Do not squash the stack during migration.

### `core`

Validate:

- `src/core/ngx_connection.h`
- `src/core/ngx_proxy_protocol.c`

The core layer must continue to provide:

- `ngx_connection_t.pqctls`
- `ngx_connection_t.pqctls_cleanup`
- `ngx_proxy_protocol_write()` passthrough of already-parsed downstream proxy
  addresses

### `http`

Validate:

- `src/http/ngx_http.c`
- `src/http/ngx_http.h`
- `src/http/ngx_http_core_module.c`
- `src/http/ngx_http_core_module.h`
- `src/http/ngx_http_request.c`
- `src/http/ngx_http_request.h`

The HTTP layer must continue to provide:

- `listen ... pqctls` parsing
- address-conf propagation of the `pqctls` flag
- `ngx_http_start_request()`
- HTTP connection handoff into the PQCTLS module handshake path

### `stream`

Validate:

- `src/stream/ngx_stream.c`
- `src/stream/ngx_stream.h`
- `src/stream/ngx_stream_core_module.c`
- `src/stream/ngx_stream_handler.c`

The stream layer must continue to provide:

- `listen ... pqctls` parsing
- stream address-conf/session propagation of the `pqctls` flag
- handoff into `ngx_stream_pqctls_module`

## Build Verification

After rebasing/cherry-picking, verify that NGINX still builds with the addon
modules from the PQCTLS repository:

```bash
PQCTLS_ROOT=/path/to/PQCTLS
PQCTLS_BUILD=$PQCTLS_ROOT/build/x86_64-linux-debug
OPENSSL_ROOT_DIR=/path/to/tongsuo-install

cd /path/to/nginx

./auto/configure \
    --with-http_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --add-module=$PQCTLS_ROOT/contrib/nginx/ngx_http_pqctls_module \
    --add-module=$PQCTLS_ROOT/contrib/nginx/ngx_stream_pqctls_module \
    --with-cc-opt="-I$OPENSSL_ROOT_DIR/include" \
    --with-ld-opt="-L$PQCTLS_BUILD/capi -L$PQCTLS_BUILD/handshake -L$PQCTLS_BUILD/codec -L$PQCTLS_BUILD/crypto -L$PQCTLS_BUILD/certs -L$OPENSSL_ROOT_DIR/lib64 -Wl,--start-group -lpqctls_capi -lpqctls_handshake -lpqctls_codec -lpqctls_crypto -lpqc_certs -Wl,--end-group -lcrypto -lstdc++"

make -j"$(nproc)"
```

## Regression Tests

Run both smoke tests from the PQCTLS repository against the rebuilt NGINX
binary:

```bash
bash $PQCTLS_ROOT/contrib/nginx/tests/test_http_pqctls_curl.sh \
    /path/to/nginx/objs/nginx \
    $PQCTLS_BUILD \
    /home/midraos/projects/curl/build-pqctls/src/curl

LD_LIBRARY_PATH=$OPENSSL_ROOT_DIR/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH} \
    bash $PQCTLS_ROOT/contrib/nginx/tests/test_stream_pqctls.sh \
    /path/to/nginx/objs/nginx \
    $PQCTLS_BUILD
```

Required pass criteria:

- NGINX config test succeeds
- HTTP `curl --pqctls--> nginx --> upstream_server` passes
- stream `pqctls` smoke test passes

## Publishing

Once migration is verified:

```bash
git push -u origin pqctls/release-1.30.0
```

Then update PQCTLS documentation so it points at the new maintained NGINX
branch, instead of referring to an in-repo core patch file.
