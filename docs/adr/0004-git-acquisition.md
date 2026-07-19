# ADR 0004: Git and archive acquisition

Status: accepted
Date: 18 July 2026

## Context

The prototype accepts HTTP(S) URLs and calls `git clone --depth 1`. Git can invoke protocol helpers, credential helpers, SSH configuration, filters, LFS, hooks, and configuration from several scopes. A repository also controls paths, attributes, submodule declarations, object sizes, and checkout content. Acquisition is therefore a trust boundary, not a convenience helper.

## Decision

Repository acquisition is a versioned, isolated operation that produces an immutable tool-owned snapshot and a receipt. The source types are:

- local checkout, read directly only for Inspect/Audit and snapshotted before any executable work;
- explicit HTTPS remote;
- explicit SSH remote through the approved SSH broker;
- local archive after validation;
- prebuilt source/evidence bundle for local-only operation.

Plain HTTP, unauthenticated `git://`, `file://`, local paths interpreted as remotes, `ext::`, external remote helpers, bundle URIs, and unknown schemes are denied by default. Redirects are bounded; a scheme or host change requires a new allow decision. URL userinfo and secret-like query material are rejected before logging. Logs retain a redacted origin and immutable commit, never credentials.

### Git process policy

Acquisition starts from an allowlisted environment. It sets `GIT_CONFIG_NOSYSTEM=1`, points global/system config at empty tool-owned files, disables terminal prompting, and supplies fixed config entries. At minimum:

- `protocol.allow=never` with only `protocol.https.allow=always` and `protocol.ssh.allow=always` for the selected source;
- `protocol.file.allow=never` and `protocol.ext.allow=never`;
- `core.hooksPath` set to an empty tool-owned directory;
- global attributes and excludes set to empty tool-owned files;
- `credential.helper=` to clear inherited helpers, followed only by the selected broker;
- `credential.useHttpPath=true` for HTTPS;
- `GIT_LFS_SKIP_SMUDGE=1` and no automatic LFS fetch;
- no recursive submodules, remote submodules, or filter/smudge execution;
- no user-supplied upload-pack, receive-pack, template, reference, alternates, or arbitrary `-c` options.

The initial clone is `--no-checkout` into a new private directory. The core resolves the requested ref to a commit, validates advertised and fetched object limits, rewrites the tool-owned local Git config to a fixed allowlist, inventories `.gitattributes`, `.gitmodules`, paths, modes, and object sizes without checkout, then materializes a snapshot under path and quota controls. Partial clone is optional and not a security control; missing blobs are fetched only under the same host/protocol/budget policy.

Git's official configuration documents `protocol.allow` and per-protocol policies. Its clone documentation confirms that submodules require explicit recursion and that partial clone filters can defer blobs. PROMPTECTOMY still sets all choices explicitly rather than relying on defaults: [git-config](https://git-scm.com/docs/git-config), [git-clone](https://git-scm.com/docs/git-clone).

### Credentials and SSH

Credentials are acquired just in time through one scoped broker. The product may use an explicitly selected OS/Git Credential Manager, host CLI OAuth broker, or SSH agent. It never copies a credential store, embeds credentials in a URL, writes tokens into snapshot/config/logs, or exposes them to Codex tools, repository code, generated code, or the executor.

Git credential helpers are executable programs, including possible shell snippets, according to [gitcredentials](https://git-scm.com/docs/gitcredentials). Therefore arbitrary inherited helpers are not executed. The user selects a reviewed broker, and the broker receives only the approved host/repository context.

SSH defaults to strict host-key checking, a bounded known-hosts source, batch mode, no agent forwarding, no user `ProxyCommand`/arbitrary SSH config, and an optional consented agent socket visible only to the acquisition process. Custom SSH configuration is an advanced explicit grant with a displayed command/effect summary.

### Submodules, LFS, filters, and dependencies

- `.gitmodules` is parsed as data. Submodules are not initialized by default.
- Each approved submodule is a new acquisition with its own immutable commit, origin, protocol, host, quota, depth, and receipt. Relative URLs are resolved and revalidated.
- LFS pointer files remain pointers by default. Each approved LFS batch has host, object count/size, redirect, credential, and retention limits.
- Checkout filters, smudge/clean commands, process filters, hooks, filesystem monitors, and dependency scripts never run during acquisition.
- Dependency acquisition is a later, separately consented executor step. A repository clone does not authorize package installation.

### Path, archive, and resource controls

Reject absolute paths, `..` traversal, NUL/control characters, platform device names, duplicate normalized paths, case collisions on case-insensitive targets, unsafe symlinks, special devices, nested repository confusion, excessive path length, excessive file/object count, decompression bombs, and output/log floods. Size/time/count limits are declared in preflight. Limit breaches return typed errors with cleanup status.

Archives are unpacked by a non-executing parser into a fresh tool-owned directory. Symlink/hardlink targets are validated before creation. Archive members cannot overwrite earlier normalized members.

### Snapshot and cleanup

The snapshot receipt records redacted origin, immutable commit or archive digest, dirty/untracked policy for local sources, selected roots, submodule/LFS state, path exclusions, object/file counts, tool/Git version, acquisition policy version, and final tree digest. Cleanup is idempotent and never issues force cleanup against a user repository. Pinned reports retain only declared references; deletion reports residual backups/external copies it cannot control.

## Consequences

- Private repository import can use existing user authentication without putting credentials in PROMPTECTOMY state.
- Some repositories need explicit submodule/LFS consent or cannot reach L1 until additional objects are acquired.
- Neutral configuration may differ from a developer's normal checkout. The support report must explain this.
- Git CLI remains acceptable initially because behavior is constrained and tested; `libgit2`/`gix` can be evaluated later against the same hostile corpus.

## Rejected alternatives

- Plain `git clone` with inherited user config: rejected because it can invoke executable helpers and uncontrolled behaviors.
- Copy the user's current checkout for every mode: rejected because dirty/untracked state, symlinks, and secrets need an explicit snapshot policy.
- Always recurse submodules/LFS: rejected because it expands code, network, credentials, and resource scope implicitly.
- Store a GitHub token in product state: rejected because host-specific persistent credentials are unnecessary and increase blast radius.

## Verification

Threats `GIT-*` and tests `GIT-*`, `PATH-*`, `ARCH-*`, and `PRIV-GIT-*` in [the threat model](../architecture/threat-model.md) and [testing plan](../architecture/testing-and-benchmarks.md) are mandatory before remote/private acquisition is called supported.
