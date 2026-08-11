# Realmroot Toolbox

`realmroot` is an Agent-native command line for discovering Resource Servers,
requesting task-scoped authority, and invoking OpenAPI-generated operations.
Restish is an embedded internal engine: users do not install Restish, a plugin,
or Rust.

## Install

Go 1.25.3 or newer is the only build prerequisite.

```console
go install github.com/realmroot/toolbox/cmd/realmroot@latest
```

## Commands

```console
realmroot agent enroll
realmroot agent whoami
realmroot agent request --resource-server github --scope contents:read
realmroot toolbox
realmroot toolbox github
realmroot toolbox github repos repos-get --help
realmroot toolbox github repos repos-get saltbo restish
realmroot toolbox platform agents list-agents --limit 1 --rsh-no-paginate
realmroot toolbox get https://example.com/status
```

`platform` is reserved and always maps to the Resource Server whose published
identifier is `realmroot`. Resource Server names also cannot collide with the
generic HTTP verbs.

Running `realmroot toolbox <resource-server>` prints that server's published
scopes, connection state, current authorization state, and requestable scopes.
Generated operation help prints the OpenAPI security scheme and scopes, so an
Agent can reason about the exact access request before calling an operation.

Only `get`, `head`, `post`, `put`, `patch`, and `delete` from Restish are
exposed. Restish configuration, plugin, and support commands remain private to
the embedding runtime.

## Architecture

- Realmroot identity, enrollment, DPoP proof, and credential-offer state are
  implemented in-process.
- Realmroot management calls use the generated client in
  `internal/realmrootapi`; they are not handwritten HTTP requests.
- Resource Server operation trees are generated at runtime from each server's
  published OpenAPI document by embedded Restish.
- The current Restish fork is pinned to an immutable commit. Once the embed
  changes are upstream, the replace directive can be removed without changing
  Toolbox commands or Agent logic.

Credential offers are stored under `~/.config/realmroot/agents` by default.
Access tokens and target-resource private keys are never persisted.

## Regenerate the Realmroot client

The repository commits generated Go code, but not a copy of Realmroot's
OpenAPI document. Generate directly from one unified contract:

```console
curl -fsS https://id.realmroot.dev/api/openapi.json -o /tmp/realmroot-openapi.json
make generate REALMROOT_OPENAPI=/tmp/realmroot-openapi.json
```

The generation script selects only the management operations Toolbox uses.

## Verify

```console
make verify
go vet ./...
```

Licensed under Apache-2.0.
