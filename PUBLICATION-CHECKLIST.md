# First public MVP publication checklist

Candidate: **v0.1.0-preview.1**, source only, destination **mrbrirup/Mrbr.Bastion**. Review date: **27 October 2026**. The owner selected .NET 11 RC3. This document distinguishes completed local preparation from actions that require the final public-publication decision.

## Local release preparation

- [x] README explains maturity, platform, setup, project boundaries and limitations; MIT license, contribution/security/support guidance and issue/PR templates are present.
- [x] Pin SDK `11.0.100-rc.3.26522.148`, disable roll-forward, document the preview support window, and set version `0.1.0-preview.1`.
- [x] Pin NuGet graphs for all 52 projects, use an explicit credential-free NuGet.org source, and provide locked restore verification.
- [x] Prepare CI with immutable action revisions, read-only repository permissions, both suites, TLS, secret scanning, dependency auditing and the publication-set gate. Live kernel tracing is excluded from hosted runs.
- [x] Keep local research `docs/`, deployment profiles/data, keys, archives, build outputs and temporary test evidence excluded. The publication gate rejects these paths even if force-added.
- [x] Visually review all 31 existing screenshots and inspect metadata. Retain 30 reviewed images with SHA-256 fingerprints in [the review manifest](release/screenshot-review.json). Withhold the one host software/version inventory screenshot, leave its original unchanged locally, and update the guide. Eight browser captures now have `.jpg` extensions matching their unchanged JPEG content.
- [x] Initial candidate scan: Gitleaks **8.30.1**, official Windows x64 archive checksum verified, full default rules, fully redacted results, no inline allowlist bypass. **Zero findings.**
- [x] Initial direct/transitive NuGet vulnerability audit: **52 projects, zero reported vulnerable dependencies**, no feed problems. This is a point-in-time known-advisory check.
- [x] Verify the Git candidate and full history with Gitleaks; validate links/exclusions/image fingerprints. The source archive and separate SHA-256 checksum are prepared locally for final publication review.
- [x] Build/test a clean clone of the committed source using the pinned SDK and locked dependencies; record exact results below.

## Clean-checkout validation

Verified source commit: **`5bdb82a9f6e77f480b33f079ca1529165e81bac5`**. The following documentation-only commit records the results; production source, tests, build configuration, dependency locks, CI, scripts and reviewed images are identical. The aggregate [verification record](release/verification.json) includes hashes of the private raw reports.

| Check | Result |
| --- | --- |
| Clean local Git clone, no existing `bin/obj` or deployment state | Passed; tracked tree remained clean after verification |
| Exact SDK, Release build, `CI=true`, locked restore | SDK `11.0.100-rc.3.26522.148`; **0 warnings, 0 errors** |
| Core suite | **384 passed, 0 failed, 0 skipped**; 2 live kernel ETW tests explicitly excluded |
| WinForms/configuration suite | **6 passed, 0 failed, 0 skipped** |
| TLS integration | Passed: pinned HTTPS HTTP/1.1 and HTTP/2 delivery plus heartbeat auditing/health; no certificate trust-store changes |
| Direct/transitive NuGet audit | **52 projects; 0 reported vulnerable dependencies; 0 feed problems** |
| Candidate and full-history Gitleaks 8.30.1 scans | **0 findings**, default rules, fully redacted, inline allowlist comments disabled |
| Public-file gate | All projects locked; relative documentation links valid; 30 reviewed image hashes/formats/metadata checked; private paths excluded |

The first attempt used an empty package cache and exposed two fixture failures. The TLS fixture now imports a temporary current-user Windows key for Schannel, retaining certificate pinning. The executable inventory fixture now uses the inspected semantic release version rather than assuming 1.x; its synthetic advisory still has to produce an affected finding. Test cleanup also retries transient Windows SHM access-denied errors after child termination without changing ACLs. The corrected final clone reused only the downloaded NuGet packages and performed a complete fresh build and both suites successfully.

Historical GUI retention evidence in the configuration guide is separate from this RC3 automated verification. Live elevated ETW is deliberately outside this run; its prior GUI runs are documented with their actual losses and recovery results. Raw TRX/logs, test keys and temporary state remain ignored locally. No public repository, remote push or GitHub CI run has occurred yet.

## GitHub publication — final review required

- [ ] Approve creation of the public repository and publication of the concrete reviewed source candidate.
- [ ] Create the remote at the selected destination; push reviewed `main` without private local state or prior test artifacts.
- [ ] Enable and read back private vulnerability reporting; verify the private report entry point in [SECURITY.md](SECURITY.md). Until then, do not submit sensitive reports through public issues.
- [ ] Enable/check GitHub secret scanning and push protection where available. Gitleaks and manual review complement these protections.
- [ ] Record successful GitHub CI for the published candidate; local verification does not establish that hosted CI works.
- [ ] Publish immutable tag `v0.1.0-preview.1` as a GitHub **prerelease**, with source-only release notes and source archive/checksum. No binary packages are promised.

The local scanner and screenshot review are a scoped credential/privacy review. They are not an independent security assessment, proof that all vulnerabilities are absent, legal certification, or a production readiness claim. The local `docs/` and `tmp/` trees were intentionally excluded from publication and are not sanitized for sharing.
