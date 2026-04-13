# NGINX `pqctls` Patch Stack

This directory documents the `pqctls` core integration maintained in this
repository as a patch stack on top of upstream NGINX release tags.

Maintenance model:

- Branch naming: `pqctls/release-<nginx-tag>`
- Current maintained branch: `pqctls/release-1.29.8`
- Commit layering:
  - `core`: shared connection and proxy-protocol hooks
  - `http`: HTTP listener and request-path plumbing
  - `stream`: stream listener and session-path plumbing

Scope of this repository:

- NGINX core changes required by `listen ... pqctls`
- Branches rebased onto upstream NGINX release tags

Out of scope for this repository:

- `ngx_http_pqctls_module`
- `ngx_stream_pqctls_module`
- PQCTLS smoke tests and helper tools

Those live in the PQCTLS repository:

- `https://github.com/gevikhn/PQCTLS/tree/master/contrib/nginx`

For release-to-release migration instructions, see
[`VERSION_MIGRATION.md`](./VERSION_MIGRATION.md).
