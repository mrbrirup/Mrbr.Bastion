# First public MVP publication checklist

Published: [**v0.1.0-preview.1**](https://github.com/mrbrirup/Mrbr.Bastion/releases/tag/v0.1.0-preview.1), source only, at **mrbrirup/Mrbr.Bastion** on **27 October 2026**. The owner selected .NET 11 RC3 and explicitly approved public publication of the reviewed candidate. This main-branch record completes the checklist after publication; the release tag preserves the reviewed candidate and its original pre-publication documentation.

## Local release preparation

- [x] README explains maturity, platform, setup, project boundaries and limitations; MIT license, contribution/security/support guidance and issue/PR templates are present.
- [x] Pin SDK `11.0.100-rc.3.26522.148`, disable roll-forward, document the preview support window, and set version `0.1.0-preview.1`.
- [x] Pin NuGet graphs for all 52 projects, use an explicit credential-free NuGet.org source, and provide locked restore verification.
- [x] Prepare CI with immutable action revisions, read-only repository permissions, both suites, TLS, secret scanning, dependency auditing and the publication-set gate. Live kernel tracing is excluded from hosted runs.
- [x] Keep local research `docs/`, deployment profiles/data, keys, archives, build outputs and temporary test evidence excluded. The publication gate rejects these paths even if force-added.
- [x] Visually review all 31 existing screenshots and inspect metadata. Retain 30 reviewed images with SHA-256 fingerprints in [the review manifest](release/screenshot-review.json). Withhold the one host software/version inventory screenshot, leave its original unchanged locally, and update the guide. Eight browser captures now have `.jpg` extensions matching their unchanged JPEG content.
- [x] Initial candidate scan: Gitleaks **8.30.1**, official Windows x64 archive checksum verified, full default rules, fully redacted results, no inline allowlist bypass. **Zero findings.**
- [x] Initial direct/transitive NuGet vulnerability audit: **52 projects, zero reported vulnerable dependencies**, no feed problems. This is a point-in-time known-advisory check.
- [x] Verify the Git candidate and full history with Gitleaks; validate links/exclusions/image fingerprints. The source ZIP, file manifest and SHA-256 checksums are published as release assets and were downloaded and verified after publication.
- [x] Build/test a clean clone of the committed source using the pinned SDK and locked dependencies; record exact results below.

## Clean-checkout validation

Locally verified source commit: **`5bdb82a9f6e77f480b33f079ca1529165e81bac5`**. Released commit: **`f15ed97565bfc99e57a70f92415bdb10dd1e3b6d`**. The difference contains only documentation and the validation record; production source, tests, build configuration, dependency locks, CI, scripts and reviewed images are identical. The aggregate [verification record](release/verification.json) includes hashes of the private local reports and the hosted verification result. Later main-branch publication updates are documentation only.

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

Historical GUI retention evidence in the configuration guide is separate from this RC3 automated verification. Live elevated ETW is deliberately outside this run; its prior GUI runs are documented with their actual losses and recovery results. Local raw TRX/logs, test keys and temporary state remain ignored. Hosted verification reports are retained as CI artifacts for 14 days; no deployment state is included in the public source or release assets.

## GitHub publication — completed

- [x] Owner approved creation of the public repository and publication of reviewed commit `f15ed97` on 27 October 2026.
- [x] Created the public repository and `origin`; pushed reviewed `main`. Verified the public tree contains exactly 341 files, with private roots and the withheld screenshot absent. GitHub identifies the license as MIT.
- [x] Enabled and read back private vulnerability reporting (`enabled: true`). The private report URL in [SECURITY.md](SECURITY.md) redirects anonymous visitors to GitHub sign-in. No synthetic vulnerability report was submitted.
- [x] Enabled and read back GitHub secret scanning and push protection (`status: enabled` for both). Gitleaks and manual review complement these protections.
- [x] [GitHub CI run 40532647144](https://github.com/mrbrirup/Mrbr.Bastion/actions/runs/40532647144) passed for released commit `f15ed97`: **383 core tests passed, one standard-user-only check skipped on the elevated runner, 6 desktop tests passed**, TLS passed, no secret findings and no reported vulnerable dependencies. Two live kernel ETW tests were explicitly excluded.
- [x] Published annotated tag `v0.1.0-preview.1` pointing to the exact reviewed commit, as a public **prerelease**, with source-only notes, ZIP, manifest and `SHA256SUMS`. Verified `isDraft: false`, `isPrerelease: true`, the tag target and downloaded asset checksums. The tag and assets are left unchanged; no binaries are distributed.

Source ZIP SHA-256: `8d51335ea5985fccc72e8355c5f96d42ddcd69ea512835206b446ef9bec8456c`.

The local scanner and screenshot review are a scoped credential/privacy review. They are not an independent security assessment, proof that all vulnerabilities are absent, legal certification, or a production readiness claim. The local `docs/` and `tmp/` trees were intentionally excluded from publication and are not sanitized for sharing.
