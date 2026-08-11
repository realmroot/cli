# Realmroot Toolbox

`realmroot` is an Agent-native command line for discovering Resource Servers,
requesting task-scoped authority, and invoking OpenAPI-generated operations.
Restish is an embedded internal engine: users do not install Restish, a plugin,
or Rust.

## Install

Go 1.25.3 or newer is the only build prerequisite.

```console
git clone https://github.com/realmroot/toolbox.git
cd toolbox
make install
```

## Commands

```console
realmroot agent enroll
realmroot agent whoami
realmroot agent request --resource-server github --scope contents:read
realmroot toolbox
realmroot toolbox github
realmroot toolbox cloudflare --search "list zones"
realmroot toolbox cloudflare --scope zone.read
realmroot toolbox cloudflare --all
realmroot toolbox github repos repos-get --help
realmroot toolbox github repos repos-get saltbo restish
realmroot toolbox platform agents list-agents --limit 1 --no-paginate
realmroot toolbox get https://example.com/status
realmroot toolbox agent-wallet wallet show --json
realmroot exec github -- git fetch origin
realmroot exec github -- gh pr list --repo realmroot/realmroot
realmroot exec cloudflare -- wrangler deployments list --name realmroot-adapters
```

`realmroot exec <resource-server> -- <native-command>` runs only native tools
advertised by that Resource Server. Git, GitHub CLI, and Wrangler keep their
normal command syntax, terminal behavior, and exit status. The child process
receives a high-entropy process-local broker credential, never the GitHub App
installation token or Cloudflare OAuth token. Existing provider credentials
are removed from its environment.

GitHub execution supports REST, GraphQL, and Git Smart HTTP. Git commits made
through `realmroot exec github -- git ...` use the stable Agent name and
`<subject>@agents.realmroot.dev` email without changing repository or global
Git configuration. Cloudflare execution redirects Wrangler's API base to the
Cloudflare Resource Server and retains its native subcommands.

`exec` consumes the exact active credential binding created by `realmroot
agent request`; it never opens approval, requests access, or expands scopes.

`platform` is reserved and always maps to the Resource Server whose published
identifier is `realmroot`. Resource Server names also cannot collide with the
generic HTTP verbs.

Running `realmroot toolbox <resource-server>` prints that server's connection
state and capability inventory. Small APIs include every published scope,
authorization detail, and generated operation with its exact required scopes.
Large APIs automatically use a compact summary so discovery cannot flood an
Agent's context. Use `--search` to match commands, summaries, methods, paths,
and operation IDs; use `--scope` to find operations requiring one exact scope.
Search results have both row and output-size limits unless `--all` is explicit.

The root `realmroot toolbox` inventory is always a Resource Server summary.
Its JSON form includes `scopeCount` and currently authorized scopes, but not
the complete requestable scope collection. Resource overview JSON follows the
same expanded, compact, and filtered modes as text output.

When a Resource Server returns the Realmroot interactive Resource profile, the
same command opens its controller approval page, waits on the canonical
Resource URL using the authenticated client, and prints the terminal
representation. Use `--no-browser` to print the URL without opening it.

Only the generic `get`, `head`, `post`, `put`, `patch`, and `delete` operations
are exposed alongside Resource Server commands. Engine configuration, plugin,
and support commands remain private to the embedding runtime. Public flags use
Toolbox names such as `--output`, `--header`, `--timeout`, and `--no-paginate`.

## Architecture

- Realmroot identity, enrollment, DPoP proof, and credential-offer state are
  implemented in-process.
- Realmroot management calls use the generated client in
  `internal/realmrootapi`; they are not handwritten HTTP requests.
- Resource Server operation trees are generated at runtime from each server's
  published OpenAPI document by embedded Restish.
- The current Restish fork module is pinned to an immutable commit. Once the
  embed changes are upstream, only the module import path changes; Toolbox
  commands and Agent logic remain unchanged.

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
