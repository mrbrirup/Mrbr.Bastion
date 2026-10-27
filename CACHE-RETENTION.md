# Cache retention and verifiable archives

Retention applies to both agent outboxes. It is **disabled by default**. Enabling it moves an eligible settled prefix out of SQLite into write-once archive files, preserving the original signed blocks and settlement receipts. Ledger identities, sequence numbers, chain tips, wire formats and central enrollment stay unchanged.

`Mrbr.Bastion.Archiving` owns the portable archive format, manifest signatures, bounded readers and file verification. `Mrbr.Bastion.Cache` owns eligibility, the SQLite catalog, atomic pruning, background maintenance and compaction. `Mrbr.Bastion.Cache.Tool` provides stopped-host maintenance and public-key-only archive verification. The configuration app exposes the same policy and cache operations.

## Safety and retention policy

- Only a **contiguous prefix** with verified settlement receipts is eligible. An unsettled block stops the pass; later settled blocks cannot be archived across that gap.
- Both the block's creation time and its signed receipt's acceptance time must satisfy the minimum age. The newest configured number of blocks remains resident regardless of age.
- A segment preserves the exact stored block/receipt JSON bytes. Its signed manifest binds its node, ledger, sequence range, predecessor/tail hashes, payload total, framed-data digest, archive identity and previous manifest hash.
- The file is created without overwriting another file, flushed, and reopened for verification before pruning. Windows uses write-through I/O plus `Flush(true)`; POSIX publication also syncs directory entries. SQLite deletes the matching original rows and commits the catalog/head in one `synchronous=FULL` transaction.
- A pre-commit failure leaves the original rows. A committed prune references a complete verified archive. Cancellation, quota failures and inaccessible archive storage do not authorize discarding unsettled rows.
- Unexpected SQLite triggers and foreign keys on cache-owned tables are rejected before migration and pruning, preventing hidden cascades from deleting other evidence.
- Archives are never expired automatically. Missing or corrupt referenced history fails verification. Keep archived files and the database together; an archive is part of the ledger, rather than an optional backup.

Flush durability depends on the filesystem, storage and any remote server honoring flush requests. See [.NET FileStream.Flush](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.flush), [Windows file metadata caching](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching) and [SQLite WAL](https://www.sqlite.org/wal.html).

## Configuration

| Setting | Default | Meaning |
| --- | ---: | --- |
| `enabled` | `false` | Opt in to automatic archiving. Disabling maintenance does not bypass existing archives during verification. |
| `archiveDirectory` | empty | Reuse the location recorded in an existing cache; otherwise use `<database>.archives`. An explicit relative root resolves against the **database folder**. A ledger-ID subfolder keeps ledgers separate. |
| `keepRecentBlocks` | `128` | Protect the newest blocks, including pending blocks. |
| `minimumAgeSeconds` | `60` | Minimum signed block/receipt age. Zero permits immediate eligible archiving. |
| `intervalSeconds` | `30` | Automatic maintenance interval. |
| `maximumBlocksPerSegment` | `1024` | Bound records in one segment; supported range 1–10,000. The payload/file limits also apply. |
| `maximumSegmentPayloadBytes` | `16,777,216` | Bound payload bytes copied into one segment. Must accommodate a maximum-size block. |
| `maximumSegmentFileBytes` | `67,108,864` | Bound the complete framed file, allowing for JSON, receipts and manifest overhead. |
| `maximumSegmentsPerRun` | `8` | Bound one maintenance pass. A later pass resumes from the committed archive head. |
| `maximumArchiveBytes` | `10,737,418,240` | Per-ledger archive-file quota. Includes unreferenced `.bastion-archive` files. Zero removes this configured quota. |

`maximumStoredPayloadBytes` now limits **resident** payload bytes. It defaults to 536,870,912 bytes for both agents. `CacheStatus.StoredPayloadBytes` continues reporting total retained logical payload, including archives, so signed heartbeat storage counters preserve their meaning. `CacheStorageStatus` separately reports resident/archived blocks and payload, published archive file bytes, segment count, resolved directory and the last retention error.

The policy must leave enough resident capacity for its recent window, minimum age, unsettled backlog and maintenance interval. Capacity pressure attempts eligible retention before rejecting an append. A pending gap, a protected recent window or insufficient archive storage can still exhaust capacity; the cache fails explicitly and retains its existing evidence.

Automatic pruning makes SQLite pages reusable. Its database file can remain at a previous high-water size. **Compact caches** / `compact` explicitly verifies history, checkpoints WAL and runs `VACUUM` to return space to the filesystem. Run it with hosts stopped and sufficient working space; it can take time for a large database.

## Configuration app

1. Stop the components and close the old control panel before rebuilding/restarting the updated app. Existing profiles load with retention disabled. Upgrade both agents and the control panel before enabling archiving; older cache implementations cannot open a pruned ledger.
2. In **Telemetry collector**, set **Maximum Stored Payload Bytes** and expand **Retention**. In **Software inventory**, configure its independent **Retention** and resident capacity.
3. Choose archive storage and quotas, set the recent window and minimum age, then enable the policy. Press **F1** or select a field for contextual help. Preserve the existing database paths and keys to retain enrollment.
4. **Save**, **Validate**, then **Export**. Export writes `server.json`, `inventory.json`, and `collector-retention.local.json`. **Start selected** also exports them before launching.
5. The **Storage** menu and collector/inventory PropertyGrid verbs offer **Verify cache history**, **Archive settled caches**, and **Compact caches**. They require stopped managed components and the exclusive outbox writer lock. Archive saves the current profile first and performs one bounded pass on enabled selected caches. The log reports actual archived/resident counts and paths.
6. Start monitoring. Both agents run maintenance while collecting and delivering. Send-only delivery also performs a configured pass after delivery. Integrity failures stop the affected operation; retryable storage failures are reported and retried at the maintenance interval.

An existing cache records its archive location when pruning commits. Empty configuration reuses that location. To relocate, stop the hosts, copy the complete history, explicitly configure the new archive root, then verify before removing the old copy. A successfully verified explicit relocation updates the recorded location. Preserve the ledger-ID subfolder and archive filenames.

## Command-line operation

Copy [cache-retention.example.json](config/cache-retention.example.json) to the deployment and edit it. Its `enabled: true` is an explicit opt-in when supplied to a command.

```powershell
dotnet run --project samples/Mrbr.Bastion.Console -- server-01 `
  "C:\Bastion\data\telemetry-outbox.db" "C:\Bastion\keys\node-private.pem" `
  "C:\Bastion\keys\receiver-public.pem" http https://receiver.example:7443 `
  --cache-capacity-mb 512 --retention-config "C:\Bastion\cache-retention.json"
```

`--cache-capacity-bytes` accepts an exact byte capacity instead of MB. Both units require at least 4 MiB. `--retain` and `--compact` are maintenance modes that do not start ETW; use the same four identity/path arguments and retention configuration, without a transport address. `--inspect` verifies combined history and prints storage information. Retention-config archive paths resolve against the cache database folder, consistently with the inventory agent.

Inventory settings use a nested `retention` object; see [inventory-agent.example.json](config/inventory-agent.example.json). Each inventory ledger still needs its existing enrollment and explicitly enabled inventory payload codec.

For a dedicated operator tool, copy [cache-maintenance.example.json](config/cache-maintenance.example.json) into the deployment. Set its node/database/key paths and policy; set `inventoryPayloads` to `true` for an inventory outbox. Ordinary settings paths resolve against this JSON file's folder, and its archive root resolves against the database folder.

```powershell
dotnet run --project Mrbr.Bastion.Cache.Tool -- status  "C:\Bastion\cache-maintenance.json"
dotnet run --project Mrbr.Bastion.Cache.Tool -- retain  "C:\Bastion\cache-maintenance.json"
dotnet run --project Mrbr.Bastion.Cache.Tool -- verify  "C:\Bastion\cache-maintenance.json"
dotnet run --project Mrbr.Bastion.Cache.Tool -- compact "C:\Bastion\cache-maintenance.json"
```

These commands require an existing outbox and stopped hosts. Opening verifies the combined history; `status`/`verify` do not prune. `retain` performs one bounded pass, so repeat it or allow the automatic worker to continue when more settled history is eligible. Status includes the first pending sequence, referenced segments and unreferenced files. The tool never adopts or deletes an unreferenced file automatically.

An exported archive can be verified without a private key:

```powershell
dotnet run --project Mrbr.Bastion.Cache.Tool -- verify-archive `
  "C:\Bastion\data\archives\LEDGER_ID\ARCHIVE_ID.bastion-archive" `
  "C:\Bastion\keys\node-public.pem" "C:\Bastion\keys\receiver-public.pem"
```

Append `--inventory` for inventory payloads. Verification checks every original signature, exact receipt binding, sequence/predecessor, record count, payload total, manifest signature and file digest. A single-file result proves that segment; complete-history verification additionally checks all catalog links and the resident suffix.

## Audits, restart and backup

Startup and explicit verification fully scan archive contents and the resident suffix, optionally against an external `LedgerCheckpoint`. Checkpoints inside an archived segment remain valid. Receipt reconciliation remains idempotent for archived blocks.

On Windows, the cache holds fully verified archives open with read sharing and no write/delete sharing. Heartbeats recheck file identity/path, signed catalog links and resident evidence; they can reuse the verified pinned bytes. Explicit verification always rescans. Other platforms rescan archive contents for heartbeat verification, so their audit cost grows with history. [Windows sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) remain in effect until handles close. Stop the hosts before moving or replacing archives.

Heartbeat snapshots remain consistent while appends and receipt commits proceed through SQLite WAL. Immutable archives are retained when an older read snapshot still needs them. The combined logical tip and byte count remain unchanged by retention, and central signed heartbeat history continues without counter rollback or re-enrollment.

For backup, stop the hosts and maintenance, then preserve the SQLite database **and all referenced archive files**. Preserve trusted public keys and externally stored checkpoints; protect private signing keys separately. Archives contain the original telemetry and need the same access controls and backup care as the outbox. A database-only backup after pruning is incomplete. Restoring an older whole database/catalog still requires a trusted external checkpoint or central anchor to detect rollback, as before.

A crash before catalog commit can leave a complete or partial unreferenced file. It is not evidence that resident rows were removed. Inspect it with the tool, check the verified database/catalog, and keep it until recovery/export decisions are made. Quota accounting includes these files, and automatic maintenance does not silently remove them.

Receiver ingestion, signed heartbeat, alert and notification history remain in their existing stores. This milestone preserves those histories and their existing capacity rules; it does not expire central records. Archive quota exhaustion or physical storage exhaustion still requires operator action.

## Verification

Regression coverage uses isolated temporary ledgers, real signatures and SQLite transactions. It exercises pending gaps, age/recent-window protection, quota failure, missing/corrupt archives, disabled maintenance over existing archives, recorded locations, old trusted anchors, capacity-pressure fallback, archived duplicate receipts, inventory codecs, compaction, portable public-key verification, and signed heartbeat continuity after repeated retention.

Child-process tests kill maintenance after file flush, before prune commit and after commit. Recovery verifies the original rows or complete archived history, then appends with the same ledger identity and predecessor. Windows tests also check that archive writes are denied while pinned and that normal heartbeats reuse pinned verification while explicit scrubs reread it. Existing local test profiles, keys, databases and archives are not modified by these fixture tests.

The [retention-enabled configuration-app run](CONFIGURATION-GUIDE.md#17-retention-enabled-end-to-end-verification) records actual screenshots and an isolated live check: 575 pending blocks were preserved unchanged during GUI archiving, then settled and archived; all 2,506 blocks and six signed audits verified after delivery and compaction. It also preserves the initial run's queue-loss finding and the bounded recovery result. See the [functionality/MVP assessment](FUNCTIONALITY-AND-MVP.md) for remaining operational work.
