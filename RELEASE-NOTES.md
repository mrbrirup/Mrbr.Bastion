# v0.1.0-preview.1 — source-only developer MVP

First public source-only developer prerelease, published 27 October 2026 at [mrbrirup/Mrbr.Bastion](https://github.com/mrbrirup/Mrbr.Bastion/releases/tag/v0.1.0-preview.1), after owner approval and successful hosted CI. The project was previously named ChronoGuard.

## Included functionality

- Windows process/file observation with correlated process lifetimes and reported parent context, configurable filtering, batching, graceful draining and loss counters.
- Signed, hash-chained SQLite outboxes; HTTP and gRPC delivery; central block verification and signed settlement receipts.
- Signed heartbeat challenges and audit history, monitoring-health scoring, central dashboard, named operators and role-based permissions.
- Durable alerts and email/webhook delivery with retries; software inventory, resumable bounded crawlers and reviewed CPE/NVD exposure correlation.
- WinForms PropertyGrid configuration, PEM provisioning, HTTPS setup helpers, explicit node enrollment, account bootstrap and local component controls.
- Configurable agent cache retention, signed settled archives, historical verification and stopped-host maintenance. Pending blocks remain resident; archival does not discard their bodies.

See the [functionality assessment](FUNCTIONALITY-AND-MVP.md) for project boundaries, implemented behavior, priorities and administrative gaps. The [configuration guide](CONFIGURATION-GUIDE.md) records the local end-to-end runs, results and reviewed screenshots. One historical host software/version screenshot is withheld from the public source for privacy; the original is retained locally.

## Build and verification

Use Windows and the exact **.NET 11 RC3 SDK `11.0.100-rc.3.26522.148`** in [global.json](global.json). This is a deliberate developer-preview baseline; roll-forward is disabled. Microsoft lists the RC3 go-live support window as 25 October–10 November 2026 in its [support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core). Reassess the toolchain before relying on a deployment after that window. Visual Studio must support the selected SDK; the documented CLI build is the release verification baseline.

Run `pwsh -File scripts/Verify-Release.ps1 -IncludeTls`. It uses locked NuGet restore, builds the full solution, runs both automated suites plus TLS, excludes live kernel ETW, and audits direct/transitive dependencies. The clean-clone Release build passed with **0 warnings/errors, 384 core tests and 6 desktop tests passed**, including TLS; two live ETW tests were explicitly excluded. The point-in-time dependency audit reported no vulnerable packages. The [publication checklist](PUBLICATION-CHECKLIST.md) records local and hosted evidence separately. No certificates are trusted or system services installed by that verification script.

[Hosted CI for the released commit](https://github.com/mrbrirup/Mrbr.Bastion/actions/runs/40532647144) passed: **383 core tests and 6 desktop tests**, including TLS; one standard-user-only test was skipped on the elevated hosted runner. The two live ETW tests remained explicitly excluded. Full-history Gitleaks and the direct/transitive dependency audit reported zero findings. Release assets contain the reviewed source ZIP, a file-by-file SHA-256 manifest and `SHA256SUMS`; downloaded assets were checked against those checksums.

## Limits and deployment expectations

This release distributes source, with an MIT license for the project's original code. NuGet dependencies retain their own licenses and are restored separately. There are no prebuilt binaries, installers, runtime keys or default operator credentials.

Short local runs establish useful evidence, not sustained production capacity. A 32,768-event queue dropped 3,550 events in the first retention test; the subsequent 131,072-event recovery run reported zero queue/source loss and zero final unpersisted events. These observations do not guarantee loss-free operation on other workloads. The recorded retention test preserved 575 pending bodies byte-for-byte, later delivered all 2,506 blocks and retained six signed heartbeat audits.

Monitoring health is pipeline health. Signatures authenticate reporting keys; they do not certify an uncompromised endpoint or complete capture. Reported parent relationships and CVE matches are investigation signals with coverage limits. Telemetry and private key files require appropriate filesystem/volume protection; stored evidence is not encrypted by the application.

Priorities before unattended production include endurance/capacity qualification, central-store retention, tested backup/restore, services and deployment packaging, key rotation, operational storage views, investigation search, and independent security review. Follow [SECURITY.md](SECURITY.md) and [SUPPORT.md](SUPPORT.md).
