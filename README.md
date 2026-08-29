# Realmroot Toolbox

`realmroot` is an Agent-native command line for discovering Resource Servers,
requesting task-scoped authority, and invoking OpenAPI-generated operations.
Users install one command and do not need a separate plugin or runtime.

## Install

Webi installs the prebuilt binary on macOS, Linux, or Windows without Go, npm,
Homebrew, or another language toolchain. On macOS or Linux:

```console
curl -sS https://webi.sh/realmroot | sh
```

On Windows, from PowerShell:

```powershell
curl.exe -fsSA "MS" https://webi.ms/realmroot | powershell
```

Open a new shell after installation, or load Webi's environment in the current
POSIX shell with `source ~/.config/envman/PATH.env`. Confirm the installed build
with `realmroot version`.

To upgrade to the latest stable release or select an explicit released version:

```console
webi realmroot@stable
webi realmroot@0.4.2
```

Webi selects the release archive for the current operating system and
architecture and verifies it against that release's `checksums.txt` before
extracting it. Supported targets are macOS, Linux, and Windows on amd64 and
arm64.

The `webi.sh/realmroot` and `webi.ms/realmroot` URLs become available only
after the Realmroot package is merged into
[`webinstall/webi-installers`](https://github.com/webinstall/webi-installers)
and deployed by Webi. Until then, automation can use the Realmroot-owned bridge
installer from the immutable commit below. Pin both the installer commit and
the CLI release version; `stable` intentionally follows future releases.

On macOS or Linux:

```console
curl -fsSLo /tmp/install-realmroot.sh \
  https://raw.githubusercontent.com/realmroot/cli/a6451ece639d24b46b11e16dac4b0ee0d9d1b8bb/scripts/install-realmroot.sh
echo '96c47a9d9295654c6110446a42194af47f22f8c9a6606689749bc0a50acb31c6  /tmp/install-realmroot.sh' \
  | shasum -a 256 -c -
REALMROOT_VERSION=0.4.2 sh /tmp/install-realmroot.sh
```

On Windows PowerShell:

```powershell
$installer = "$Env:TEMP\install-realmroot.ps1"
Invoke-WebRequest `
  https://raw.githubusercontent.com/realmroot/cli/a6451ece639d24b46b11e16dac4b0ee0d9d1b8bb/scripts/install-realmroot.ps1 `
  -OutFile $installer
if ((Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne `
    '8eebe604e181d27ec0425b76ab949386174b3af9db493ebf8ab17bc0a6dbbaa0') {
  throw 'Realmroot installer checksum mismatch'
}
& $installer -Version 0.4.2
```

These bridge installers use the same `~/.local` versioned layout as Webi and
fail before extraction unless the archive matches the selected GitHub
release's `checksums.txt`. They are not aliases for the pending Webi package;
switch automation to the canonical Webi URLs after the upstream deployment.

Homebrew installs a prebuilt macOS or Linux binary and does not require Go:

```console
brew install realmroot/tap/realmroot
```

Prebuilt archives for macOS, Linux, and Windows are available from
[GitHub Releases](https://github.com/realmroot/cli/releases). Verify manual
downloads against the published `checksums.txt` before installing the
`realmroot` binary on your `PATH`.

Go developers can install directly from the module:

```console
go install github.com/realmroot/cli@latest
```

To build the current checkout instead:

```console
git clone https://github.com/realmroot/cli.git
cd cli
make install
```

## Commands

```console
realmroot agent enroll --username mira --nickname "Mira Chen"
realmroot agent whoami
realmroot version
realmroot toolbox
realmroot toolbox github
realmroot toolbox sync github
realmroot toolbox github context
realmroot toolbox github context show realmroot
realmroot toolbox github context use realmroot
realmroot agent request --resource-server github --context realmroot --scope contents:read
realmroot toolbox cloudflare --search "list zones"
realmroot toolbox cloudflare --scope zone.read
realmroot toolbox cloudflare --all
realmroot toolbox github repos repos-get --help
realmroot toolbox github repos repos-get saltbo restish
realmroot toolbox platform agents list-agents --limit 1 --no-paginate
realmroot toolbox get platform/resource-servers
realmroot toolbox agent-wallet wallet show --json
realmroot exec
realmroot exec github
realmroot exec github -- git fetch origin
realmroot exec github -- gh pr list --repo realmroot/realmroot
realmroot exec github --context realmroot -- gh pr merge 42 --repo realmroot/realmroot
realmroot exec cloudflare -- wrangler deployments list --name realmroot-adapters
```

Enrollment always requires the immutable Agent username. Add `--nickname` to
choose a display nickname; otherwise Toolbox uses the detected runtime as the
nickname. Realmroot stores the runtime separately and never derives the
username from either field. Start with a short lowercase human handle such as
`mira`; only choose another available handle when enrollment reports a conflict.

Release builds can embed traceable build information:

```console
make build VERSION=v0.2.0 COMMIT=<git-commit> BUILD_TIME=<rfc3339-time>
realmroot version --json
```

`realmroot exec <resource-server> -- <native-command>` runs only native tools
advertised by that Resource Server. Git, GitHub CLI, and Wrangler keep their
normal command syntax, terminal behavior, and exit status. The child process
receives a high-entropy process-local broker credential, never the GitHub App
installation token or Cloudflare OAuth token. Existing provider credentials
are removed from its environment.

Run `realmroot exec` to list every advertised native command, or `realmroot
exec <resource-server>` to inspect one Resource Server. The same native command
inventory is included in `realmroot toolbox <resource-server>` output.

GitHub execution supports REST, GraphQL, and Git Smart HTTP. Git commits made
through `realmroot exec github -- git ...` use the Agent's immutable username as
the author name and `<username>@agents.realmroot.dev` as the email without
changing repository or global Git configuration. Cloudflare execution redirects Wrangler's API base to the
Cloudflare Resource Server and retains its native subcommands. When Cloudflare
returns a short-lived asset-upload credential, the broker keeps it in memory
and accepts it only for that account's asset-upload path during the same exec
session.

Use `realmroot toolbox <resource-server> context` to list accounts, workspaces,
installations, or other Contexts defined by that Resource Server. `context show`
prints its service-defined description and safe attributes; `context use`
selects the default. Context selection is independent of permission requests
and credential storage.

Use `realmroot toolbox sync <resource-server>` after that Resource Server
publishes a changed OpenAPI contract. Sync bypasses the cached OpenAPI document
and atomically refreshes the generated command catalog. It does not request
Resource authority or change the selected Context.

Generated operations automatically choose the least-privileged approved offer
inside the selected Context. `agent request`, generated operations, and `exec`
accept `--context <name>` as a one-command override without changing the
default. `exec` uses all already-approved authority in that Context so opaque
native protocols such as GraphQL work without exposing scope-selection or
credential-selection internals. It never requests or expands authority.

Generic HTTP operations address registered Resource Servers by Toolbox name,
for example `realmroot toolbox get github/repos/realmroot/cli`. Toolbox resolves
the deployment URL and selects operation authority without exposing either to
the caller. Absolute URLs remain available only for unregistered public HTTP
targets.

`platform` and `sync` are reserved Toolbox command names. `platform` always maps to the Resource Server whose published
identifier is `realmroot`. Resource Server names also cannot collide with the
generic HTTP verbs.

Running `realmroot toolbox <resource-server>` prints that server's connection
state and capability inventory. Small APIs include every published scope,
Context summary, and generated operation with its exact required scopes.
When the Resource Server origin publishes an Agent Skills Discovery v0.2.0
index, the overview also includes each Skill's Level 1 metadata and advertised
artifact digest. It also emits a copyable `npx skills add` command targeting
the detected Agent runtime when the installer supports it; other runtimes get
a runtime-neutral command so the installer can discover an available target.
Toolbox does not download archives or execute Skill scripts during discovery.
Large APIs automatically use a compact summary so discovery cannot flood an
Agent's context. Connected-account scopes and current Agent authority are
labeled separately. Use `--search` to match commands, summaries, methods,
paths, and operation IDs; use `--scope` to find operations requiring one exact
scope. Scope-filtered results contain only the matching authorization
alternatives. Search results have both row and output-size limits unless
`--all` is explicit.

The root `realmroot toolbox` inventory is always a Resource Server summary.
Its JSON form includes `scopeCount` and connected-account scopes, but not the
complete requestable scope collection. Resource overview JSON follows the same
expanded, compact, and filtered modes as text output and does not expose
credential schemes or bindings.

When a Resource Server returns the Realmroot interactive Resource profile, the
same command opens its controller approval page, waits on the canonical
Resource URL using the authenticated client, and prints the terminal
representation. Use `--no-browser` to print the URL without opening it.

Only the generic `get`, `head`, `post`, `put`, `patch`, and `delete` operations
are exposed alongside Resource Server commands. Engine configuration, plugin,
and support commands remain private to the embedding runtime. Public flags use
Toolbox names such as `--output`, `--header`, `--include`, `--timeout`, and `--no-paginate`.
Engine profiles and explicit credential selection are not part of the public
command surface. Authorization-detail payloads and credential references remain
internal and are never printed as Context selection instructions.

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
