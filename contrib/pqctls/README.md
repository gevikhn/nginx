# NGINX `pqctls` Patch Stack

This directory owns the NGINX-side `pqctls` integration maintained as a patch
stack on top of upstream NGINX release branches.

Maintenance model:

- Branch naming: `pqctls/release-<nginx-version>`
- Current maintained branch: `pqctls/release-1.31`
- Commit layering:
  - `core`: shared connection and proxy-protocol hooks
  - `http`: HTTP listener and request-path plumbing
  - `stream`: stream listener and session-path plumbing
  - `contrib`: HTTP/stream addon modules and smoke tests
  - `docs`: maintenance, build, and migration notes

Scope of this repository:

- NGINX core changes required by `listen ... pqctls`
- HTTP and stream `pqctls` addon modules
- NGINX smoke tests and NGINX-specific helper scripts
- Branches rebased onto upstream NGINX release branches

Scope of the PQCTLS repository:

- `pqctls_capi.h` and PQCTLS libraries
- PQCTLS client/server helper binaries used by the tests

For release-to-release migration instructions, see
[`VERSION_MIGRATION.md`](./VERSION_MIGRATION.md).
