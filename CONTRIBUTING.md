# Contributing to Mrbr.Bastion

Use the SDK selected by [global.json](global.json). Windows is required for live ETW collection and Windows inventory sources. Run ordinary development and tests without elevation; elevate only when deliberately testing live kernel ETW collection.

## Local validation

From the repository root:

```powershell
pwsh -File scripts/Verify-Release.ps1 -IncludeTls
python scripts/check_publication.py --include-untracked
```

PowerShell 7 and Python 3.11+ are required for the release helpers. Verification performs locked restore, full Release build, both automated suites and a direct/transitive dependency audit. `-IncludeTls` enables the TLS fixture without trusting a development certificate in the OS. Reports are written under ignored `artifacts/verification/`.

The live ETW tests require an elevated Windows test host and are excluded by the release helper and [CI workflow](.github/workflows/ci.yml). Run them deliberately in an isolated elevated environment when changing collection behavior. Run ordinary development without elevation. CI enables TLS but never starts live kernel ETW implicitly.

Dependency versions are locked in each project's `packages.lock.json`. For an intentional dependency update, edit the package reference, run `dotnet restore Mrbr.Bastion.slnx --force-evaluate`, review every changed lock file, then run the locked verification. Do not accept a changed graph merely to silence a vulnerability audit.

Before committing, run the publication gate against the staged set without `--include-untracked`. It checks required exclusions, clone-relative documentation links, dependency lock files, screenshot formats/metadata and exact reviewed image hashes. New or changed screenshots require a visual credential/privacy review and an updated [review manifest](release/screenshot-review.json); do not automatically approve image hashes. Keep host inventory screenshots private or use deliberately synthetic data.

Use the official pinned Gitleaks scanner for both the candidate directory and Git history. The helper downloads its Windows x64 archive from the official release and verifies its checksum:

```powershell
$scanner = & ./scripts/Get-Gitleaks.ps1
& $scanner git . --redact=100 --ignore-gitleaks-allow
```

CI uses full history, default detection rules and fully redacted reports. Do not add broad exceptions for test directories or documentation. Inspect false positives narrowly; never include real keys or credentials in fixtures. A scanner pass complements manual review and does not prove the code is secure.

## Changes and review

- Keep contract/domain, persistence, transport, hosting, and UI responsibilities in their existing projects. Add a separate project when a new responsibility needs its own dependencies or lifecycle.
- Follow [.editorconfig](.editorconfig) and nearby code conventions. Avoid unrelated formatting changes.
- Add focused tests for changed behavior, especially signatures, canonical encoding, persistence recovery, authorization, and retry/idempotency rules. Do not silently change wire formats or existing SQLite data semantics.
- Describe the problem, resulting behavior, compatibility implications, and validation in a pull request. Include a synthetic screenshot when changing dashboard behavior that benefits from visual review.
- Keep configuration templates usable and free of credentials. Update the README and relevant examples when setup changes. `docs/` contains local research and is deliberately excluded from Git; clone-critical instructions belong in tracked files.

Use synthetic evidence in tests and issue reports. Keep local databases, keys, passwords, session tokens, and real host telemetry out of commits. See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

Contributions are made under the repository's [MIT license](LICENSE).
