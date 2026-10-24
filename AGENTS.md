# AGENTS.md

## Project

fdarun is a macOS-only Rust CLI that lets allowlisted launchd jobs run a
program with Full Disk Access. See the README for the security model, which
every change must keep.

- `src/main.rs`: the clap CLI and its commands.
- `src/allowlist.rs`: `/etc/fdarun.toml`, loaded only when root controls it.
- `src/caller.rs`: the calling job's label and domain.
- `src/run.rs`: argv and hash checks, then `exec`.

## Commands

```sh
mise run test       # cargo nextest
mise run fix-all    # fix lint and formatting
mise run check-all  # every linter via hk: clippy, rustfmt, cargo-deny, ...
```

Run cargo through mise (`mise exec -- cargo ...` outside an activated shell).

## Rules

- Keep dependencies few; every one ends up with Full Disk Access.
- Fail closed: if anything can't be checked, refuse.
- Keep functions plain and testable with values passed in (paths, uids,
  environment), not read from the process inside the logic.
- Pin GitHub Actions by commit SHA and give each job the least permissions.
  Don't use caches in the release workflows.
- Tool config lives in `.config/`, apart from `.typos.toml`, `.oxfmtrc.json`
  and `deny.toml`, which their tools only read from the root.
