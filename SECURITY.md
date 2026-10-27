# Security

## Reporting a vulnerability

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/mrbrirup/Mrbr.Bastion/security/advisories/new). It is enabled and was verified on 27 October 2026; anonymous visitors are directed to GitHub sign-in. The [publication checklist](PUBLICATION-CHECKLIST.md) records the configuration checks. If the channel becomes unavailable, ask the maintainer to establish a private channel before sharing technical details. A public issue requesting a private contact must contain no exploit details, credentials or real host evidence.

Once a private channel is available, include the affected revision, environment, a minimal reproduction using synthetic data, and the expected and observed behavior. Remove private signing keys, passwords, bearer/session tokens, database contents, and identifying telemetry from reports.

## Deployment considerations

- Provision and protect persistent node signing keys, trusted public keys, and HTTPS certificates outside source control. The server requires explicit node/ledger enrollment.
- Prefer named operator accounts and the minimum required roles. Bootstrap and administrator recovery require local access to the operator database with the server stopped.
- Restrict access to SQLite files, backups, configuration, and telemetry. Stored payloads can contain paths, command lines, and user identifiers; they are not encrypted by this implementation.
- A signed observation authenticates its reporting key. It does not establish complete capture or the trustworthiness of a compromised endpoint. External checkpoints are needed to detect ledger rollback behind a trusted anchor.
- Monitor storage quotas and delivery failures. Settled evidence is retained; capacity exhaustion does not silently purge pending evidence.

## Supported baseline

`v0.1.0-preview.1` is a source-only developer preview, pinned to the .NET 11 RC3 SDK in [global.json](global.json). See [release notes](RELEASE-NOTES.md) for its short prerelease support window and deployment limits. There is no security response SLA or commitment to maintain older preview revisions. Review dependency advisories and the toolchain support window before evaluation; report findings against the exact revision.
