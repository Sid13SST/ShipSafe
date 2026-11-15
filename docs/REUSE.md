# Using ShipSafe's gates from another repository

ShipSafe's five gates are reusable workflows (`on: workflow_call`). Another
repository can call them and get the same pass/fail behaviour, the same
fail-closed rules and the same self-tested scripts.

> These are automated checks in CI, not a security guarantee. A green run
> means "these tools, with these rules and today's advisory data, found
> nothing at run time". The severity policy (e.g. only fixable HIGH/CRITICAL
> container vulnerabilities fail) is ShipSafe's chosen default; adopt it only
> after reviewing it for your context.

Copy-paste starting point: [`docs/examples/consumer-security-gates.yml`](examples/consumer-security-gates.yml).

## How it works

Each reusable workflow:

1. checks out **your** repository (the code to scan);
2. checks out **ShipSafe** at the commit you pin (`tooling-repository` /
   `tooling-ref`) and moves it to `$RUNNER_TEMP/shipsafe`, outside your
   workspace, so the gate never scans ShipSafe's own deliberately vulnerable
   fixtures as if they were your code;
3. installs the gate's tool from ShipSafe's pinned, hash-/checksum-verified
   install scripts and runs ShipSafe's gate script against your workspace.

What comes from where:

| From your repository | From the pinned ShipSafe commit |
|----------------------|---------------------------------|
| code, lock files, Dockerfiles, build context | gate scripts (`scripts/*.py`) |
| `.shipsafe/waivers.yml` (your exceptions) | tool install scripts + pinned hashes |
| `.gitleaks.toml` if you have one | Semgrep rules (`rules/semgrep/`) |
| the `exclude` / `forbid-paths` / `skip-dirs` you pass | `.hadolint.yaml` (threshold: warning) |

ShipSafe's own `.gitleaks.toml` (which allowlists ShipSafe's `fixtures/`) is
**never** applied to your repository. Without your own `.gitleaks.toml`, the
secrets gate uses Gitleaks' default rules with no allowlist.
`scripts/verify_reuse.sh` (CI job `reuse-self-test`) checks this, by running
every gate from a separate tooling copy against a throwaway consumer repo.

## Pinning (required)

Use the **same full 40-character commit SHA** in both places:

```yaml
uses: Sid13SST/ShipSafe/.github/workflows/sast.yml@<SHA>
with:
  tooling-repository: Sid13SST/ShipSafe
  tooling-ref: "<SHA>"
```

- A caller from another repository that passes a branch, tag or short SHA as
  `tooling-ref` fails at the first step. Tags and branches can be moved; in
  March 2026 attackers force-pushed tags of the `trivy-action` GitHub Action
  to malicious commits (CVE-2026-33634).
- GitHub does not expose the `@<SHA>` of the `uses:` line to the called
  workflow, so ShipSafe cannot check that the two SHAs match. Keeping them
  identical is the caller's responsibility. Dependabot updates only the
  `uses:` SHA, not the `tooling-ref` string: when it opens a bump PR, update
  `tooling-ref` to the same SHA in that PR, or the new workflow definition
  would run the old scripts.
- Review the ShipSafe diff before moving to a new SHA, as you would for any
  third-party action.

## While ShipSafe is private

- In ShipSafe: Settings -> Actions -> General -> Access: allow access from
  repositories owned by the same user/organisation. Only those repositories
  can call the workflows.
- The second checkout needs read access to ShipSafe. The caller's
  `GITHUB_TOKEN` cannot read another private repository, so pass a
  fine-grained token with **Contents: read** on ShipSafe only:
  `secrets: { tooling-token: ${{ secrets.SHIPSAFE_READ_TOKEN }} }`.
- If ShipSafe becomes public, drop the token.

## Inputs common to every gate workflow

| Input / secret | Default | Meaning |
|----------------|---------|---------|
| `tooling-repository` | the calling repository | where ShipSafe's scripts come from; set `Sid13SST/ShipSafe` |
| `tooling-ref` | the triggering commit | ShipSafe commit to run; must be a full SHA cross-repo |
| `tooling-token` (secret) | `github.token` | read token for a private ShipSafe |
| `python-version` | `3.13` | Python for the gate script |

Gate-specific inputs (`requirements`, `targets`/`exclude`/`forbid-paths`,
`mode`/`config`, `discover`, `context`/`image`/`config-dir`/`skip-dirs`) are
described in each workflow file.

## Exceptions in your repository

Add time-boxed waivers in your own `.shipsafe/waivers.yml` (format in
`docs/DESIGN.md`, "Waivers"). Expired waivers fail the gate; secrets findings
cannot be waived.

## Code-scanning upload (SARIF) - optional, not used here

GitHub code scanning can display findings from SARIF files. It is free for
public repositories but needs GitHub Advanced Security on private ones, so
ShipSafe (private) does not upload SARIF. For a public repository you could
add `--format sarif` runs of the tools plus `github/codeql-action/upload-sarif`
(pinned by SHA, with `security-events: write` on that job only). ShipSafe's
pass/fail verdict would still come from its own gate scripts, not from code
scanning.
