# Desktop configuration and run control

See the [illustrated configuration guide](../CONFIGURATION-GUIDE.md) for mouse/keyboard steps, exact example inputs, screenshots, and verified results.

Set **Mrbr.Bastion.Desktop** as the Visual Studio startup project. Build the solution in Debug or Release, then start the application. The profile's **Runtime binaries → Build configuration** must match that build. The UI detects the solution directory when launched from its normal build output. Published `.exe`/`.dll` overrides are available for installations without source.

The PropertyGrid edits the real receiver and inventory configuration models. Expand nested objects, use the `[…]` button to browse paths or edit collections, and select a property to read its description. F1 opens contextual help. The links beneath the grid expose commands for the selected section; the menus and toolbar expose the same operations.

Ctrl+1 through Ctrl+6 select the six sections. Ctrl+S saves a profile, Ctrl+E exports runtime JSON, Ctrl+L validates, and Ctrl+Shift+F5 requests Stop all. Ctrl+Shift+F12 (File → Save screenshot) saves the current application view as a PNG beneath the deployment directory's `screenshots/` folder. Save uses an unused default `desktop.bastion.local.json` in the deployment directory on first use; Save as chooses a different filename.

Keyboard access is also available for **Create keys** (`Ctrl+Shift+K`), **Initialize and enroll** (`Ctrl+Shift+I`), **Start selected** (`Ctrl+Shift+F6`), **Verify cache history** (`Ctrl+Shift+V`), **Archive settled caches** (`Ctrl+Shift+A`) and **Compact caches** (`Ctrl+Shift+C`). The same validation and stopped-component requirements apply to keyboard, menu and PropertyGrid commands.

For a new local deployment:

1. Choose **Workspace → Deployment directory**. Relative key, database, and configuration paths resolve there. The default is `%LOCALAPPDATA%\Mrbr.Bastion\default`.
2. Set the save locations in **Signing keys**. **Create keys** generates missing receiver/node P-256 pairs and verifies existing complete pairs; it refuses to overwrite existing files. It applies the paths to the agent/receiver settings. Private files have an explicit current-user-only ACL. **Verify keys** checks the key pairing and fingerprints.
3. Configure the node IDs and transport addresses. Use **Initialize and enroll** with all components stopped. It opens/creates the selected outboxes and adds their exact ledger identities to the receiver's enrollment collection; existing identities and trust entries are retained.
4. Configure receiver HTTPS. An empty certificate path uses an existing ASP.NET Core development certificate. **Check HTTPS certificate** checks the current user; **Trust development certificate** explicitly requests local development trust. For other deployments select a suitable PFX. Signing PEM files are not TLS certificates.
5. With the receiver stopped, use **Create administrator** to bootstrap an empty named-user operator store. Enter a matching password of 15–128 characters. Existing stores require the established administrator/recovery workflow, not another bootstrap.
6. Use **Validate**, **Save**, and **Export**. Saving writes a desktop profile; exporting writes `server.json`, `inventory.json` and `collector-retention.local.json`. **Start selected** also exports the runtime files before launching the selected components in receiver/inventory/collector order, so the collector knows its managed peers when tracing begins.
7. Use **Stop all** to request graceful shutdown of inventory, collector, then receiver, allowing accepted collector work to drain. This uses an authenticated, current-user-only local pipe. **Force stop** is a separate confirmed command and can lose uncommitted observations. Closing the UI offers graceful shutdown of its managed processes.

For same-host operation, **Telemetry collector → Exclude managed process file I/O** defaults to true. The collector excludes file activity from itself, this panel, and the exact live receiver/inventory processes launched by this panel. Process lifecycle and parent evidence remain collected; descendants and other processes accessing the same files remain visible. Starting a peer later refreshes the policy over the authenticated control pipe. Process names and directory names do not grant exclusions.

The collector PropertyGrid also exposes queue capacity, batch size, partial-batch flush interval and ETW buffer size. Defaults are 8192 events, 100 events, 1000 ms and 64 MB. Review the signed audit counters under a representative workload before sustained collection: filtering and larger buffers cannot guarantee unlimited capacity.

For a bounded check, set **Workspace → Selected run duration seconds** (for example, `120`), save, then click **Start selected**. Zero means continuous operation. A bounded run saves an application screenshot halfway through, requests graceful **Stop all** at the deadline, then saves a final screenshot and command log under the deployment directory's `screenshots/` and `logs/` folders. Individual **Start receiver/collector/inventory** commands do not arm this timer. Manual **Stop all** cancels it.

Keep the configuration window restored for screenshots; it can be behind the browser. Minimized windows render only their title bar, so the screenshot command reports that the window must be restored.

Both agent sections expose **Retention** and resident **Maximum Stored Payload Bytes**. Retention defaults to disabled; enable it after choosing archive storage, quotas and a recent/age window. The **Storage** menu and PropertyGrid verbs verify history, archive eligible settled blocks, or compact selected caches with components stopped. Archive files remain required history. See [cache retention](../CACHE-RETENTION.md) before enabling it or relocating a deployment. Close this application before rebuilding/restarting the updated UI.

The receiver hosts the dashboard. Enable its Dashboard settings and use **Open dashboard**. Enable receiver Software settings and the inventory agent for software/CVE features. Enable inventory **Process events** for live process lineage. Live ETW requires elevation: run Visual Studio or this application as Administrator; **Help → Restart elevated** saves the profile and requests an elevated restart.

Passwords, bearer/access tokens, webhook signing secrets, NVD API keys, and PFX passwords are masked and session-only. They are omitted from saved/exported JSON and passed directly through the child process environment. Re-enter them after loading a profile, or provision them in the service environment. A profile records key file paths, never PEM contents. Do not commit deployment profiles, private keys or databases.

The control panel manages local processes. For remote monitored systems, use a separate profile on each machine, provision only the appropriate private key and trusted public keys, transfer explicit public-key/ledger enrollment to the receiver, and set a reachable HTTPS address. It does not install Windows services or execute on remote hosts. Review software/CPE mappings through the authorized central dashboard.

The configuration/orchestration layer is in `Mrbr.Bastion.Configuration`, which adapts the existing executable configuration contracts. WinForms presentation and editors remain in `Mrbr.Bastion.Desktop`; shared optional shutdown support is in `Mrbr.Bastion.Hosting`.
