# Repository publication policy

The public repository is a product and contributor surface, not a transcript of the development environment.

## Keep

- product source, tests, schemas, fixtures required by tests, and lockfiles;
- README, Quickstart, contributor guidance, security and governance files;
- accepted ADRs, architecture, threat, privacy, compatibility, and release evidence;
- minimal assets used by the product or its documentation.

## Exclude

- local agent memory, plans, transcripts, prompts, handoffs, and tool configuration;
- submission forms, copied event guides, private contact details, and demo preparation notes;
- generated patches and replacements;
- runtime state, caches, reports containing local paths, screenshots, videos, and build output;
- credentials, environment files, auth stores, or private source and evidence.

`AGENTS.md` is retained because it is portable contributor guidance. Tool-specific files such as `CLAUDE.md`, `.claude/`, and `.codex/` are local configuration and are excluded.

## History publication

Removing a path from the current tree does not remove it from Git history. Before the first stable public release:

1. create a recoverable mirror clone of every ref;
2. rewrite only the approved excluded path set in that mirror;
3. run secret, privacy, large-object, and generated-content scans across every rewritten ref;
4. verify source, tests, lockfiles, release artifacts, authorship, commit messages, and branch topology;
5. run clean builds and tests from the rewritten candidate;
6. replace remote refs only after the explicit release approval;
7. verify the public repository from an anonymous clean clone.

History rewriting preserves the logical sequence but changes commit identifiers. Existing signatures and external commit links cannot survive it. This is why it happens once, immediately before publication, rather than during normal development.

## Branch and worktree policy

Development happens on a short-lived `zc/` branch. The release candidate fast-forwards `main` only after all gates pass. Temporary branches and worktrees are removed after their commits are either integrated or explicitly rejected. No generated or private local file may be absorbed during that operation.
