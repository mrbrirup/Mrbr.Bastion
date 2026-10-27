# Mrbr.Bastion

Mrbr.Bastion collects Windows process and file observations and commits signed batches to a durable local outbox. It includes HTTP/gRPC delivery, signed settlement receipts, heartbeat audits, monitoring-health scoring, an operator dashboard with named users and roles, durable email/webhook alerts, software inventory and CVE exposure correlation. The project was previously named ChronoGuard.

This is the **v0.1.0-preview.1 source-only developer MVP**, targeting `net11.0`. Install the exact .NET 11 RC3 SDK selected by [global.json](global.json): `11.0.100-rc.3.26522.148`. SDK roll-forward is disabled for this preview's reproducible validation. Windows is required for kernel ETW, Windows inventory sources and the WinForms app. The central service and portable components are separate from those collectors. No prebuilt executables, installers, signing keys or default credentials are distributed.

The current solution is an early developer MVP. See the [functionality, roadmap and MVP assessment](FUNCTIONALITY-AND-MVP.md) for implemented capabilities, remaining work, administrative requirements and publication criteria. The [retention-enabled end-to-end record](CONFIGURATION-GUIDE.md#17-retention-enabled-end-to-end-verification) includes measured results and actual screenshots. These short local runs do not establish unattended production capacity.

Read the [release notes](RELEASE-NOTES.md), [publication checklist and review](PUBLICATION-CHECKLIST.md), and [security policy](SECURITY.md) before deployment. This preview is for controlled evaluation and adaptation. Storage is finite, collection can drop events under pressure, and monitoring-health scores do not certify that a host is uncompromised. The toolchain is prerelease; review its support window before relying on a deployment.

## Project boundaries

| Project | Responsibility |
| --- | --- |
| `Mrbr.Bastion.Abstraction` | Telemetry models, source/monitor/cache interfaces, signing contracts, block and receipt models, and canonical protocol encoding. No external packages. |
| `Mrbr.Bastion.Core` | Windows kernel ETW collection, process lifetime correlation, filtering, batching, shutdown draining, and collection-health counters. Depends on Abstraction and TraceEvent. |
| `Mrbr.Bastion.Cache` | SQLite outbox, signatures, hash chaining, capacity limits, startup integrity verification, and receipt reconciliation. Depends on Abstraction, without a reference to Core. |
| `Mrbr.Bastion.Archiving` | Portable write-once ledger archives, signed manifests, exact block/receipt verification, and pinned Windows archive readers. |
| `Mrbr.Bastion.Cache.Tool` | Stopped-host cache retention, full-history verification, compaction, storage/catalog inspection and public-key archive verification. |
| `Mrbr.Bastion.Cryptography` | P-256 signing and explicit trusted-key verification. |
| `Mrbr.Bastion.Transport*`, `Mrbr.Bastion.Grpc` | Delivery lifecycle, HTTP/gRPC clients, and gRPC protocol. |
| `Mrbr.Bastion.Ingestion*` | Central block verification, durable ingestion, and settlement receipt APIs. |
| `Mrbr.Bastion.Auditing*`, `Mrbr.Bastion.Health` | Signed heartbeat challenges/responses, audit history, and monitoring-health scoring. |
| `Mrbr.Bastion.Alerting*`, `Mrbr.Bastion.Operations*` | Durable alerts, server summaries, and background health evaluation. |
| `Mrbr.Bastion.Notifications*` | Durable delivery queue, retry workers, SMTP, and webhooks. |
| `Mrbr.Bastion.Inventory*` | Inventory contracts, discovery, Windows sources, resumable file/archive crawling, persistence, and agent. |
| `Mrbr.Bastion.Vulnerabilities*`, `Mrbr.Bastion.Software.Hosting` | Reviewed software/CPE mappings, cached NVD intelligence, exposure correlation, and hosting. |
| `Mrbr.Bastion.Operators*` | Operator identities, permissions, password/session security, SQLite persistence, HTTP integration, and offline administration. |
| `Mrbr.Bastion.Dashboard` | Operator web UI and authorized dashboard APIs. |
| `Mrbr.Bastion.Server` | Central service composition and deployment configuration. |
| `samples/Mrbr.Bastion.Console`, `tests/` | Collector sample, integration/unit tests, and crash-recovery probe. |
| `Mrbr.Bastion.Desktop`, `Mrbr.Bastion.Configuration` | WinForms PropertyGrid configuration, PEM provisioning, enrollment, administration bootstrap, and local process orchestration. |
| `Mrbr.Bastion.Hosting` | Optional authenticated, current-user-only shutdown and file-I/O policy updates for managed processes. |

The console sample composes monitoring, caching, delivery, and signed heartbeat auditing. Domain/contracts, persistence, transport, hosting, and UI responsibilities remain in separate projects. [Mrbr.Bastion.slnx](Mrbr.Bastion.slnx) includes the complete solution.

## Build and test

```powershell
pwsh -File scripts/Verify-Release.ps1 -IncludeTls
```

Tests use temporary directories, real signatures, and real SQLite transactions. They cover tampering, crash recovery, transport retries, receipt verification, heartbeat health, alerts, notification delivery, inventory/exposure correlation, and operator authorization. Ordinary tests require no elevation. To deliberately include live ETW tests, run `dotnet test tests/Mrbr.Bastion.Tests/Mrbr.Bastion.Tests.csproj -c Release --no-build --no-restore` from an isolated Administrator terminal; those tests capture a child process and its file reads/writes. The release helper always excludes live ETW and enables the TLS fixture only with `-IncludeTls`.

The helper requires PowerShell 7, performs locked restore and a full Release build, runs both suites (including the opt-in TLS fixture), and audits direct/transitive NuGet dependencies. Results go to `artifacts/verification/`. For a build alone, use `dotnet restore Mrbr.Bastion.slnx --locked-mode` followed by `dotnet build Mrbr.Bastion.slnx -c Release --no-restore`.

The prepared [Windows CI workflow](.github/workflows/ci.yml) performs the same checks plus source-history secret scanning and the reviewed-file/screenshot gate. It excludes live kernel ETW capture. Hosted CI status remains pending until the repository is published. See [CONTRIBUTING.md](CONTRIBUTING.md) for development conventions and [SUPPORT.md](SUPPORT.md) for reporting problems.

## Central service setup

For a desktop setup workflow, build the solution and run **Mrbr.Bastion.Desktop** as the Visual Studio startup project. It provides PropertyGrid settings, profile save/load, runtime JSON export, key helpers, enrollment, administrator bootstrap, and local start/stop controls. See the [illustrated configuration guide](CONFIGURATION-GUIDE.md) and [desktop reference](Mrbr.Bastion.Desktop/README.md). The command-line setup below remains supported.

The example files are templates requiring enrollment and key/certificate provisioning. Keep deployment configuration and persistent data outside the checkout, for example under `C:\Bastion`.

1. Provision persistent P-256 PEM key pairs for the node and receiver. The agent uses the node private key and trusts the receiver public key; the central service uses the receiver private key and trusts explicitly enrolled node public keys. Preserve keys across restarts.
2. Copy [appsettings.example.json](Mrbr.Bastion.Server/appsettings.example.json) to `C:\Bastion\server.json`. Resolve its key paths relative to that directory and provision a trusted HTTPS certificate through Kestrel configuration or the service environment. The template listens on `https://localhost:7443` with HTTP/1.1 and HTTP/2; gRPC requires HTTP/2. For local development, a trusted ASP.NET Core development certificate can supply HTTPS.
3. Initialize the node outbox with `--inspect` (shown below). Set `Bastion:Nodes` to its exact node ID, printed ledger GUID, and public-key path. Each new ledger requires its own enrollment.
4. To enable the dashboard, merge [operator-authentication.example.json](config/operator-authentication.example.json) into the existing `Bastion:Dashboard` section. With the server stopped, bootstrap the first administrator in the same operator database:

```powershell
dotnet run --project Mrbr.Bastion.Operators.Tool -- bootstrap C:\Bastion\data\operators.db alice
```

The tool prompts for a password without echo. There are no default credentials. Bootstrap works only on an empty operator store; `recover-admin` provides offline administrator recovery and requires a password change at the next sign-in.

Start the configured service from the repository root:

```powershell
dotnet run --project Mrbr.Bastion.Server --no-launch-profile -- --config C:\Bastion\server.json
```

Relative server paths resolve against the configuration file's directory. Visit `https://localhost:7443/dashboard` when the dashboard is enabled. Named-user sessions are durable; sensitive changes revoke affected sessions and security events are retained. HTTPS is required by default. The explicit insecure-loopback option is intended for local development only.

| Role | Access |
| --- | --- |
| Viewer | Read health summaries, audit history, and alerts. |
| Operator | Viewer access, evidence details, alert acknowledgements, and delivery retries. |
| Analyst | Viewer access, evidence details, software/CPE mapping review, and intelligence searches. |
| Administrator | All permissions, including operator accounts and security history. |

Roles can be combined. Server APIs enforce permissions as well as the UI. Shared-token authentication is available only through the explicit `LegacyToken` migration mode; new deployments should use named users.

### Alerts and notifications

The server evaluates monitoring health and persists alert transitions. Set `Bastion:Notifications:Enabled` and configure its `Email` and/or `Webhooks` destinations in the server configuration to enable delivery. [NotificationRuntime.cs](Mrbr.Bastion.Server/NotificationRuntime.cs) defines the settings; [SmtpNotificationTransport.cs](Mrbr.Bastion.Notifications.Smtp/SmtpNotificationTransport.cs) and [WebhookNotificationTransport.cs](Mrbr.Bastion.Notifications.Webhooks/WebhookNotificationTransport.cs) define destination options and validation. Keep credentials in deployment configuration or environment variables, outside Git.

Delivery attempts are leased from a durable SQLite queue and use bounded retries with backoff. Failed deliveries remain visible for authorized manual retries. A downstream service may receive a delivery again after an ambiguous failure; webhook consumers should deduplicate using the supplied delivery identity. Configure outbound SMTP/HTTPS connectivity and monitor queue/storage limits.

### Software inventory and CVE exposure

Merge [software-server.example.json](config/software-server.example.json) into the same server configuration to enable inventory storage and exposure evaluation. It is a configuration fragment, not a replacement for the server settings. The NVD integration needs outbound access; an optional API key can be provided through `Bastion__Software__NvdApiKey`.

Copy [inventory-agent.example.json](config/inventory-agent.example.json) to a deployment directory and set its node ID, key paths, storage paths, and service URI. Initialize its separate outbox, then enroll its printed ledger ID and node public key on the server:

```powershell
dotnet run --project Mrbr.Bastion.Inventory.Agent -- C:\Bastion\inventory.json --inspect
dotnet run --project Mrbr.Bastion.Inventory.Agent -- C:\Bastion\inventory.json
```

Process and installed-software discovery provide observations; optional file/archive crawlers use configured roots, limits, and durable checkpoints. Enable crawlers deliberately for the intended paths. `--once` collects one pass, `--new-scan` restarts completed crawl tasks, and `--send-only` sends an existing outbox. Optional process ETW requires elevation.

Set `processEvents` to `true` in the inventory agent configuration and run it elevated to include live process events and their correlated parent context in central inventory. The software table's **Reported parent** column shows the retained name, executable path, PID, and lifetime identifier where known; the evidence download contains the full timestamps and identities. Periodic process inventory alone does not establish parent lineage.

Graceful inventory shutdown stops the event source and drains accepted process-enrichment work to its durable outbox. Metadata unavailable for short-lived or protected processes is recorded as coverage evidence.

An analyst or administrator reviews software-to-CPE mappings before matching against cached CVEs. Findings distinguish potential exposure, no match within the evaluated coverage, and unknown coverage. Product-name similarity alone does not prove vulnerability. Inventory freshness, inaccessible files, mapping uncertainty, and intelligence coverage remain visible; exposure alerts are separate from monitoring-health scores.

## Composing the library

```csharp
using Mrbr.Bastion.Cache;
using Mrbr.Bastion.Core;

// Providers implement ISignatureSigner / ISignatureVerifier. Retain historical
// public keys in blockVerifier when rotating node signing keys.
await using var cache = await DurableTelemetryCache.OpenAsync(
    new DurableCacheOptions
    {
        NodeId = "server-01",
        DatabasePath = @"C:\ProgramData\Mrbr.Bastion\cache.db"
    }, nodeSigner, blockVerifier, trustedReceiverVerifier);

var source = new WindowsEtwTelemetrySource();
var monitor = new TelemetryMonitor(source, cache, new TelemetryMonitorOptions
{
    QueueCapacity = 8192,
    BatchSize = 100,
    FlushInterval = TimeSpan.FromSeconds(1),
    Filter = observation => true
});

// Await the entire lifetime. Host cancellation stops ETW and drains accepted
// observations. Any source or storage fault is propagated through this task.
await monitor.RunAsync(shutdownToken);
```

The Windows source requires elevation and uses a unique session name with automatic session replacement disabled. Each source and monitor instance runs once. Create new instances to restart. The caller owns and disposes the cache and signing providers after the monitor task finishes. A filter exception faults collection.

The cache's `MaximumEventsPerBlock` must accommodate the monitor's `BatchSize`; the payload-byte limit must also accommodate serialized batches. Oversized batches fail explicitly. Default limits are 1,000 events per block, 4 MiB per serialized payload, and 512 MiB of resident payload bytes. SQLite pages, indexes, receipts, WAL and archive files require additional disk space.

## Console sample

First initialize the outbox and print its ledger identity for central enrollment; inspection does not start ETW:

```powershell
dotnet run --project samples/Mrbr.Bastion.Console -- server-01 C:\Bastion\data\cache.db C:\Bastion\keys\node-private.pem C:\Bastion\keys\receiver-public.pem --inspect
```

After enrollment and central service setup, run collection and delivery from an elevated Windows terminal:

```powershell
dotnet run --project samples/Mrbr.Bastion.Console -- server-01 C:\Bastion\data\cache.db C:\Bastion\keys\node-private.pem C:\Bastion\keys\receiver-public.pem http https://localhost:7443
```

The sample derives each key ID as uppercase SHA-256 of its DER SubjectPublicKeyInfo. Provision the corresponding node public key to the receiver and use the same key IDs there. Keep the node signing key stable across restarts. The sample does not generate keys or accept replacement keys silently. For production, implement the signing contracts using your protected key store or existing cryptographic libraries. The included `EcdsaSignatureProvider` wraps .NET P-256 ECDSA with SHA-256 and fixed-width IEEE P1363 signatures; PQC providers can implement the same contracts.

Ctrl+C stops ETW and commits the final accepted batch. The console reports committed events, queue overflow, source-reported ETW loss, and pending blocks. Use `grpc https://localhost:7443` in place of the HTTP arguments for gRPC delivery, or omit the transport arguments for local collection only. `--inspect` prints the ledger identity for enrollment; `--send-only` delivers a stopped outbox without ETW. `--health` inspects an existing outbox. Signed heartbeat auditing is enabled with transport; `--no-audits` disables it explicitly.

## Collection semantics

- Process events include start, exit, and startup rundown observations. Collector-local lifetime IDs distinguish observed reuse of the same PID. Missing starts/stops and ETW ordering can leave identity unknown; a PID alone is not a durable identity.
- A live process creation event can bind the reported parent PID to a lifetime already observed by the collector. The signed event copies that parent's name, executable path, first-observed time, and observed start time when available. Child file/exit observations retain this historical context even after the parent exits or its PID is reused. No later lookup substitutes the process currently occupying that PID.
- Startup rundown identifies existing processes but does not establish when they were created. A rundown child's parent PID therefore remains uncorrelated, even if another process currently has that PID. Missing parents, self-parent references, and parents first observed after a child's creation are not assigned a lifetime. Delayed old starts/stops do not replace/remove a newer observed PID lifetime.
- Parent context describes Windows' reported relationship, which can be designated separately from the caller creating the process. It does not prove a causal launcher, exploitation, or complete capture; lost creation/exit events can leave gaps. This feature supplies investigation evidence and does not automatically classify parent/child combinations as malicious or generate exploit alerts.
- File events subscribe separately to create/open, read, write, close, delete, and rename. Metadata queries are optional. An operation-start event does not establish successful completion. A reported rename path is not a guaranteed old/new path pair.
- Unavailable paths, command lines, parent identities, and user SIDs remain unknown. Device paths may remain in device-path form. Collection does not classify access as authorized, unauthorized, or remote.
- The console filters its own file I/O in the ETW callback before copying events, resolving file paths or allocating event IDs. The desktop also supplies explicit process-lifetime identities for its receiver, inventory agent and control panel, preventing their file activity from feeding back into collection. These exclusions do not include descendants or other processes accessing the same files; process start, snapshot and exit observations remain retained. Raw-source exclusions are counted in monitor health separately from queue drops and ETW loss. This is noise control and intentionally reduces file-I/O coverage for the selected processes.
- Independent CLI launches can repeat `--exclude-file-process <PID>` for known local Bastion peers; each is bound to its creation time and an open process handle. The desktop refreshes identities over its authenticated local control channel when peers start. `--include-managed-file-io` opts out of the desktop scope while keeping the collector's own file I/O excluded. Stop and restart a standalone collector to select a replacement peer lifetime.
- The source suppresses System-process I/O to its exact current ETW transport backup file when its path is resolved. Unknown paths remain evidence. Event IDs use a randomly seeded per-run sequence; restoring stored events preserves their IDs without drawing new randomness for every event. Cryptographic nonces and signatures retain their existing behavior.
- Queue and batching limits are configurable through the collector PropertyGrid or `--queue-capacity`, `--batch-size`, `--flush-ms` and `--etw-buffer-mb`. Defaults remain 8192 queued events, 100 events per batch, a 1000 ms partial-batch flush and 64 MB ETW buffers. Overflow remains observable; filtering does not turn losses into successful collection.
- The recorded same-host run used 32768 queued events and 1000-event batches, retaining 171536 events with zero reported queue/source loss. See [the configuration guide](CONFIGURATION-GUIDE.md#15-same-host-feedback-correction-and-bounded-verification) for the measured scope, signed audits, preserved failed attempts and screenshots.
- Callbacks use nonblocking `TryWrite` into a bounded channel. Queue overflow increments `QueueDroppedEvents`; source loss is reported separately through `SourceLostEvents`. Neither count proves complete capture. Health counters cover the current run and should be exported by the host if persistent collection-health history is required.
- Source failure drains accepted events before faulting. Storage or signing failure stops the source and faults the monitor, with accepted but uncommitted events counted by `UnpersistedEvents`. Those events cannot be promised durable. Disk or capacity exhaustion never silently deletes pending evidence.

## Durable commit and receipt reconciliation

Configurable agent-cache retention can archive a verified settled prefix while preserving pending blocks, ledger identity and verifiable history. It is disabled by default. Both agents and the configuration app expose the policy; see [cache retention and archiving](CACHE-RETENTION.md) for configuration, safety, maintenance commands and backup requirements. Resident capacity and archived history are accounted separately. Receiver history keeps its existing retention/capacity rules.

1. A batch is serialized once. Its exact bytes and all block identity, sequence, time, format, signing-key, and predecessor metadata are canonically encoded, hashed, and signed.
   Cache size/status queries use small metadata indexes, and pending delivery uses a partial index over unsettled blocks. The receiver's capacity query also uses a covering size index. Existing stores gain derived indexes after startup integrity verification; signed evidence, receipts and ledger identities are preserved. Full local integrity audits verify the retained chain and receipts in a read-only WAL snapshot, allowing the writer to continue committing during verification.
2. A SQLite transaction inserts the block and advances the persisted chain tip. WAL mode with `synchronous=FULL` is used. Successful `AppendAsync` acknowledges this local commit; hardware and filesystem durability still depend on honoring flush requests.
3. `ReadPendingAsync` returns individually verified pending blocks in sequence order without changing their state. The sender retries them until it receives proof of durable remote storage.
4. The receiver verifies the block before deserializing its telemetry and atomically commits the block with a signed `SettlementReceipt`. The receipt is returned only after commit succeeds. Its content is encoded with `LedgerProtocol.EncodeReceipt` and binds the node, ledger, block ID, sequence, hash, acceptance time, algorithm, and key ID.
5. `ReconcileAsync` verifies the trusted receiver signature and exact block identity before transactionally storing the receipt. Repeated valid receipts are idempotent. Out-of-order receipts leave earlier unsettled blocks pending. A transport success status does not settle anything.

A receiver must deduplicate by node/ledger/block identity and return a valid receipt again after a lost response. A duplicate delivery is not by itself an attack. A local sequence ahead of the receiver can represent an ordinary offline backlog.

Settled blocks and receipts remain available in SQLite or verifiable archives so the full chain can still be verified. The resident capacity limit includes settled payloads still in SQLite; archive quotas are separate. There is no automatic archive expiration or zero-fill routine. Monitor disk usage and configure retention before sustained deployment. Local payloads are not encrypted by this implementation; configure filesystem permissions and volume protection appropriate to the recorded paths and command lines.

## Integrity and trust limits

Opening a cache verifies every retained block's signature, payload, sequence, predecessor, row identity, and stored receipt, and checks the persisted chain tip. It rejects invalid evidence instead of resetting the ledger. The live writer also rejects an unexpected change to its known chain tip. Pending reads verify their returned blocks; full rescans use `VerifyIntegrityAsync` and should be scheduled by the host where ongoing local integrity checks are needed.

Store `CacheStatus.Checkpoint` outside the endpoint and supply that trusted checkpoint to `OpenAsync` or `VerifyIntegrityAsync` to detect rollback behind that anchor. A local hash chain alone cannot detect replacement or consistent truncation of the entire database and local metadata. A checkpoint cannot detect loss after its last anchored sequence. Keep node identities and ledger IDs distinct when provisioning a genuinely new ledger.

Only one cache writer may open a database at a time. SQLite stores the authoritative state; callers must not edit its tables or copy a live database without the SQLite backup API. Signer and verifier implementations must be thread-safe and explicitly trust the allowed algorithms and keys. A valid signature authenticates the reported evidence, not the health of an administrator-compromised host.

Parent context is an optional payload extension. Existing events and inventory records without it remain readable, and absent fields are omitted to preserve their encoding. Upgrade the central service before agents: older inventory receivers reject unknown JSON fields. The new context is included in the existing signed payload and requires no SQLite schema migration.

## Repository files and license

`docs/` and its entire contents are intentionally ignored as local research material. Build output, generated previews, temporary files, runtime databases, local configuration, and signing/certificate keys are also excluded by [.gitignore](.gitignore). Safe `*.example.json` configuration templates remain tracked.

[.editorconfig](.editorconfig) defines editing conventions and [.gitattributes](.gitattributes) defines Git text/binary and line-ending handling. See [SECURITY.md](SECURITY.md) for vulnerability reporting and deployment considerations.

Mrbr.Bastion is licensed under the [MIT license](LICENSE). Third-party packages retain their own licenses.
