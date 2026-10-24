# fdarun

Give allowlisted launchd jobs Full Disk Access on macOS.

macOS grants Full Disk Access (FDA) to an app or binary, not to a script, and
a launchd job's scripts run as whatever launchd started. fdarun is a small
binary you grant FDA to once. A job runs `fdarun exec PROGRAM [ARGUMENT ...]`,
fdarun checks that the job may run exactly that command, then replaces itself
with the program, which keeps fdarun's access.

It does the same job as LaunchControl's `fdautil`, without the app, and pins a
hash of each program so that editing a script doesn't silently keep its access.

## How it decides

The allowlist is `/etc/fdarun.toml`. Only `sudo fdarun set` writes it:

```toml
[agents."dev.example.backups"]
argv = ["/Users/me/Scripts/backups.sh"]
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

`fdarun exec` runs the program only when all of these hold:

1. Its parent is launchd (pid 1), and launchd gave it a label in
   `XPC_SERVICE_NAME`.
2. The label is under `agents` when running as a user, or `daemons` when
   running as root. A daemon with a `UserName` runs as that user, so allow it
   as an agent.
3. The command line is exactly the entry's `argv`. The program must be an
   absolute path; fdarun never searches `PATH`.
4. The program file, after following symlinks, still has the entry's SHA-256.
5. `/etc/fdarun.toml` and every directory above it are owned by root and not
   writable by group or others, and the file is not a symlink.

Otherwise it exits with an error on stderr, which launchd writes to the job's
`StandardErrorPath`.

## Threat model

fdarun stops other software running as you from using its access for anything
but the commands you allowed, and from changing an allowed program without you
noticing. It cannot protect more than that:

- `XPC_SERVICE_NAME` can be faked, so treat any allowed command line as
  runnable by anything running as you. That is safe only because the hash pins
  what it runs.
- The hash covers the program file alone, not what it loads afterwards: files
  a script sources, programs it calls, or the Python code `uv run` executes.
  Keep those somewhere only you can write, or allow them by path in their own
  jobs.
- fdarun hashes the program and then execs it, so a program changed between
  the two runs unchecked.
- Anything that changes a program, such as upgrading a tool behind a mise
  shim, stops the job until you allow it again.

## Install

Releases carry a signed [packslip](https://packslip.dev), so mise can install
fdarun and verify where it was built:

```sh
mise use -g packslip:github.com/CallumKerson/fdarun
```

FDA attaches to a path and a code signature, and mise's install path changes
with every version and is writable by you. Install a root-owned copy at a fixed
path instead, signed with a certificate of your own so FDA survives upgrades:

1. Once, create a code-signing certificate: Keychain Access → Certificate
   Assistant → Create a Certificate…, named `fdarun local`, with identity type
   Self Signed Root and certificate type Code Signing.
2. After each install or upgrade:

   ```sh
   tmp="$(mktemp)"
   cp "$(mise which fdarun)" "$tmp"
   codesign --force --sign "fdarun local" --identifier dev.kerson.fdarun "$tmp"
   sudo install -o root -g wheel -m 0755 "$tmp" /usr/local/bin/fdarun
   rm "$tmp"
   ```

3. Once, add `/usr/local/bin/fdarun` under System Settings → Privacy &
   Security → Full Disk Access.

## Usage

Allow a job, then point its `ProgramArguments` at fdarun:

```sh
sudo fdarun set agent dev.example.backups /Users/me/Scripts/backups.sh
```

```xml
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/fdarun</string>
  <string>exec</string>
  <string>/Users/me/Scripts/backups.sh</string>
</array>
```

Run `sudo fdarun set` again after changing the program, once you've checked
the change.

| Command | What it does |
| --- | --- |
| `fdarun exec PROGRAM [ARG ...]` | Run the program if the calling job may |
| `fdarun list` | List the jobs, flagging any whose program changed |
| `sudo fdarun set agent\|daemon LABEL PROGRAM [ARG ...]` | Allow a job, pinning its program |
| `sudo fdarun remove agent\|daemon LABEL` | Remove a job |
| `sudo fdarun rename agent\|daemon FROM TO` | Change a job's label |
| `fdarun test agent\|daemon LABEL PROGRAM [ARG ...]` | Check whether a job may run a command |
| `fdarun test` | Check whether this process has FDA |

macOS checks the process that started fdarun, so `fdarun test` from a terminal
reports the terminal's access. Run it from a launchd job to check fdarun's.

## Development

```sh
mise run setup      # install the git hooks
mise run test       # run the tests
mise run check-all  # run every linter
```

## Licence

[MIT](LICENSE)
