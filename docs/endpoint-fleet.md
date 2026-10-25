# Managed endpoints and evidence storage

Athernex now includes a portable Rust endpoint agent, portal-generated installer bundles, ClamAV provisioning, native process/socket snapshots, optional Linux kernel process events, network tracker events and authentication journal collection, investigation-bound response work, and malware response playbooks. The server remains a single-operator research deployment. This implementation is **not yet a validated replacement for an existing antivirus/EDR product**: Windows/macOS native prevention, tamper resistance, broader native event coverage, and platform release validation remain open requirements. Linux now has a native on-access prevention service with live blocking checks, verified automatic agent replacement, and locally permitted, portal-reviewed controller/engine replacement with rollback. Engine group promotion and failed-canary containment have passed with two native endpoint instances in an isolated Linux container; separate-host fleet reliability remains unverified.

## What is implemented

| Capability | Behavior |
| --- | --- |
| Portal | `/endpoints`: installer download, device health, capabilities, revocation, action proposal/review, receipts, and per-endpoint playbooks |
| Installation | Linux systemd unit, macOS LaunchDaemon, Windows startup task running as SYSTEM; platform binaries are built separately and checked against their release manifest |
| Enrollment | One-device, platform-bound, 15-minute token; the agent persists its own random identity and credential before enrolling; uncertain responses can be retried without registering a second device |
| Transport | HTTPS outside literal loopback; per-device credentials; no operator credential installed on endpoints; no HTTP redirect of agent credentials |
| Antivirus | Optional setup of pinned official ClamAV packages, verified by SHA-256 and size before invoking the OS installer; private signature configuration; on-demand and bounded scheduled scanning; hourly signature updates and daily scans when AV provisioning is selected |
| Linux native prevention | ClamAV daemon/monitor under an independently restarted protection process, dedicated scanner identity, live allow/deny probes, bounded durable detections, process/boot/scope health checks |
| macOS authorization development | Separate Endpoint Security adapter with bounded workers, exact-byte verdicts, durable receipts and a private response broker for scans/quarantine; verified component packaging, dedicated account/runtime setup and controller-managed scanner/adapter supervision; automatic per-root blocking health and controlled native validation gate implemented; native installation/runtime validation remains pending |
| Windows authorization development | WDK-linked NTFS minifilter and Rust client, owned development supervisor, reduced LocalService scanner token, owned fixed-capacity scratch volume with format/health/recovery checks, journaled workspace reclamation, persistent per-image network rules and durable scanner launch/recovery journal, bounded denial spool and agent outbox transfer; production controller integration, complete scanner confinement/prevention coverage, signing and native runtime validation remain pending |
| Fleet rollout | Reviewed agent or controller component and exact membership, scheduled start/deadline, bounded canary/later groups, post-installation health windows, pause/cancel, failure containment and restart recovery |
| Signed agent updates | Portal-reviewed delivery, device-bound downloads, durable staging receipts, locally pinned release key, platform/channel/sequence checks, readiness checks, rollback and interruption recovery; operator-managed or approved automatic installation |
| Signed controller updates | Independent signed history and local delivery permission; portal-reviewed staging or automatic installation under a stable launcher; Linux runtime confirmation, rollback, crash recovery and durable installation receipts verified |
| Signed engine updates | Bounded signed ClamAV trees, manual activation or exact local unattended request; real Linux blocking, configuration rollback and crash recovery verified |
| Response | Inventory, scan, signature update, exact-hash quarantine, restore, and explicitly permitted shell/PowerShell automation |
| SOAR | Malware → investigation → exact-hash quarantine, disabled/review/automatic modes per endpoint; policy revision and result preserved in the investigation |
| Evidence | Full endpoint/event identities, file paths, detection names and SHA-256 values survive durable receipt and replay; malware has its own event kind |
| Endpoint telemetry | Native process metadata and TCP/UDP socket snapshots, plus opt-in Linux kernel process events, supported SSH/PAM authentication reports and Windows Security logon reports, collected independently of management requests and endpoint actions; typed originals, delivery backlog and collection gaps are visible in the portal; evidence is scoped to the device |
| Endpoint detections | Browser/document interpreter children, interpreter external TCP connections, observed privilege changes and repeated authentication denials; process correlations retain device/boot/process identities, authentication accounts remain device-scoped, and originals survive investigation/replay |
| Investigation correlation | Malware cases include up to eight prior observations from the same endpoint and executable path within one hour; case exports retain their full typed payloads |
| Storage | Configurable live ledger budget, disk headroom admission, sealed cold-evidence segments, historical retrieval/correlation, persistent replay checks, complete verified backup |

ClamAV's upstream on-access scanner is Linux-only. Linux reports `realtime: true` only after verifying that a clean probe is readable and a signature-matched probe is denied within the configured folders. Windows/macOS still report `realtime: false`; scheduled/on-demand scans and remote quarantine do not provide pre-execution blocking. See [ClamAV on-access scanning](https://docs.clamav.net/manual/OnAccess.html). macOS native prevention requires Apple's Endpoint Security entitlement and extension deployment; Windows protected antimalware services have their own signing/ELAM requirements. See [Apple's system extension requirements](https://developer.apple.com/system-extensions/) and [Microsoft's protected antimalware service contract](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-).

## Build and download

The Windows kernel component is documented in [windows-native-adapter.md](windows-native-adapter.md).
Its unsigned development build is separate from installer catalogs and does not
enable Windows real-time protection.

```sh
make endpoint-local                 # Linux x86_64 artifact for this host's portal
make run-siem
# Sign in, open Endpoints, enter the server origin, select a build and download.
```

The catalog defaults to `.athernex/endpoint-artifacts`; set `ATHERNEX_ENDPOINT_ARTIFACTS` to a private deployment path for an installed server. The native-platform matrix in `.github/workflows/endpoint.yml` builds and runs endpoint tests plus the real-process fleet journey on Windows x86_64, Linux x86_64/ARM64, and macOS Intel/Apple silicon when executed in CI. Copy the resulting catalog artifacts into this directory. The portal refuses downloads for missing or checksum-mismatched builds. It does not fabricate a Windows/macOS installer from a Linux executable.

`tools/package_endpoint.py` verifies executable format and CPU architecture. Development artifacts say `development-unsigned`. `--require-native-signature` requires a valid Authenticode signature on Windows, or code-signing and Gatekeeper acceptance on macOS, on a matching build host. Production signing keys, Apple notarization credentials and the Endpoint Security entitlement must be provisioned separately. A successful cross-compilation is not native installation/runtime validation.

Each downloaded ZIP contains the actual executable, installer, release manifest and private enrollment configuration. Run `sudo sh install.sh` on Linux/macOS or `install.ps1` as Administrator on Windows. The Windows host must permit the installer under its execution policy. Setup preserves existing antivirus and removes its bootstrap file after successful installation. No endpoint service is installed by building this repository or by running its tests.

With **Install ClamAV** selected, the endpoint downloads the exact package in `infrastructure/endpoint/antivirus-packages.json`, verifies its size and SHA-256, installs it and initializes signatures. The pinned 1.5.4 catalog was retrieved from the [official ClamAV release](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4). Linux supports the declared DEB/RPM package families; macOS uses the vendor's universal PKG; Windows uses its x64 MSI. Package installation and signature bootstrap need network access and can take several minutes. A failed bootstrap is an error, not a healthy protection state. Antivirus engine/signature resource costs are separate from the lightweight agent; the Linux controller service allows up to 4 GiB and 128 tasks including management, protection and their children. Linux provisioning also enables native prevention for the configured scan roots (initially `/home`).

## Remote connectivity

The Rust listener remains bound to loopback. `infrastructure/endpoint/Caddyfile` is a TLS reverse-proxy example. Set `ATHERNEX_PUBLIC_HOST` for Caddy and `ATHERNEX_PUBLIC_ORIGIN=https://your-host/` for the SIEM. The proxy must replace the upstream Host with `127.0.0.1:8787`; the SIEM accepts browser mutations only from its loopback origin or the explicitly configured public origin. Remote login cookies use Secure. Use a publicly trusted certificate or configure the agent's `ca_file`; verification is never disabled.

## Endpoint policy and failure semantics

State paths are `/var/lib/athernex-endpoint` on Linux, `/Library/AthernexEndpoint/state` on macOS, and `%ProgramData%\AthernexEndpoint` on Windows. The installer restricts state to the service identity/admins. `config.json` contains the endpoint credential and must remain private.

`scan_roots` limits scan/quarantine/restore paths. `allow_scripts` defaults to false. If enabled locally, scripts execute under the service identity with the exact operator-approved content hash, output budget and deadline; this is privileged administration, not a general-purpose sandbox. Linux/macOS scripts use `/bin/sh`; Windows scripts use PowerShell without bypassing its execution policy. Portable scanner result lines are treated as candidate paths: each match is rescanned from a private snapshot (at most 100 MiB) before its hash can authorize a playbook. A changed or misleading result fails the action, and scan observations commit atomically. Quarantine requires the file's approved SHA-256 and an atomic same-filesystem move; cross-filesystem quarantine is refused. Restore refuses to overwrite an existing file.

Every remote action belongs to an open investigation and expires after 15 minutes. The server rechecks approval, endpoint state and case state at dispatch. The agent also validates endpoint identity, action hash, deadline and local policy. It durably claims the command before asking to start. After a crash, an ambiguous command becomes `interrupted` and is not automatically executed again. Operators must review partial side effects and issue new work explicitly. Revocation prevents future dispatch; it cannot undo an already executed operation.

On Linux/macOS, bounded commands have an independent process watcher before the
external executable starts. It closes inherited descriptors and registers exit
notifications for the agent and command leader. Either exit requests termination
of the command's process group, including ordinary background children. Timeout
and output budgets still apply. Cleanup waits at most 100 ms synchronously;
remaining groups retain their capacity slot until the reaper confirms they are
gone. A completed leader with unresolved group cleanup does not produce a
successful action result. Each command adds one watcher process. Containers need
an init/reaper; the Docker fixtures now use `--init`.

Linux requires permitted `pidfd_open` and `close_range` syscalls (mainline Linux
5.9 or later, or suitable backports). The installer checks support before stopping
an existing service, and commands refuse unsupported monitoring. See the
[process descriptor contract](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
and [descriptor-range contract](https://man7.org/linux/man-pages/man2/close_range.2.html).
Mac watchers use process-exit notifications and still require native runtime
validation. Process-group cleanup does not contain programs that deliberately
move descendants into other sessions/groups, change privileges, or hand work to
an external service. It does not undo completed writes or make arbitrary scripts
a sandbox.

Investigation JSON exports include the exact endpoint actions, content hashes, states, receipts and original observations associated with the case. Export refuses cases above 256 response records instead of silently truncating them; use a complete backup for larger cases. Cases with response records cannot be deleted through the case menu because receipt replay and audit depend on that retained history. Server migration requires a separate endpoint state directory; an installer cannot silently replace the existing server identity.

Events and results stay in the local SQLite outbox until the server commits them. Replay with changed content is rejected. Local event capacity is 4,096 records, with a 64 MiB SQLite ceiling; saturation is explicit. Server inventory is limited to 1,024 endpoints and 256 active response commands. Existing case/note budgets still apply. There is no claim of unlimited fleet capacity or exactly-once external side effects across machine failure.

## Linux native prevention

Linux installation with ClamAV selected runs separate management and protection processes under `athernex-controller` in `athernex-endpoint.service`. Management can restart without stopping prevention. The installer retires the previous standalone `athernex-protection.service`, starts the controller and waits for verified blocking before reporting success. `athernex-endpoint protection-status STATE_DIR --require-active` prints health and returns status 3 until protection is active. The supervisor starts `clamd` under a dedicated `athernex-av` system account and `clamonacc` with the privileges needed for fanotify prevention. Only the scanner UID is exempt from scanning; root applications remain subject to blocking. The daemon listens on a private Unix socket. Existing configurations can be prepared with `sudo athernex-endpoint configure-protection STATE_DIR`; service setup is performed by the installer. This requires a kernel/environment that permits fanotify prevention, plus the package's daemon and monitor binaries.

The configuration's `protection.roots` contains canonical watched directories. The supervisor rejects overlap with endpoint state, its database/runtime directories, or `/proc`, `/sys` and `/dev`. Signatures live in the adjacent `STATE_DIR.av/db` directory and the scanner-owned runtime is private. Root-owned probe directories named `.athernex-protection-check-*` hold harmless exact-file test fixtures. Probe creation uses directory descriptors and refuses symlinks. The same probe directories are reused after restart.

Protection health includes its scope, excluded UID, last verified time, pending detections and dropped-record count. Verification repeats every 30 seconds; health becomes degraded if its record is stale, the boot/policy changes, a child stops/dies, or a watched root/probe directory is replaced. The portal displays stale verification as unknown. These checks establish blocking for the probes and scope, not complete detection coverage or tamper resistance. A protection-process crash terminates its daemon/monitor; the controller restarts protection. A controller crash terminates both child processes on Linux; systemd restarts the controller. There is a protection gap while the monitor is absent. Scanner errors are configured to deny access while the monitor is functioning.

Native detection logs enter a separate FULL/WAL SQLite queue capped at 2,048 records and 32 MiB, then transfer into the normal outbox only after the destination commit. Native log paths are unverified and have no content hash, so they cannot authorize automatic quarantine. Repeated observations are deduplicated within their collection minute. Queue overflow increments a persistent dropped counter and degrades health without stopping blocking. The gap remains visible after the queue drains; an audited gap-acknowledgement workflow remains unfinished.

Approved Linux native scans use a restricted reader under the scanner UID with only `CAP_DAC_READ_SEARCH`. It opens files without following symlinks, streams bytes over the private daemon socket, and hashes those exact bytes. This allows private files to be scanned while protection remains active and avoids deriving actionable hashes from textual log paths. Scans admit at most 4,096 entries, 32 directory levels, 128 MiB per file and 1 GiB total, subject to the action deadline and output budget. Symlinks/special files are skipped explicitly. Budget/read/daemon failures fail the action; completed observations enter the outbox atomically. The daemon's expanded-content limit is 256 MiB with limit alerts enabled. Quarantine rechecks the approved hash using the restricted reader before moving the file, and verifies integrity afterward.

The separate [macOS authorization adapter](macos-native-adapter.md) now provides
the development transport for native open/exec/mmap decisions and transfers
immutable detection receipts into the endpoint outbox, malware investigations and
configured response playbooks. The complete receipt survives case export. Linux
transport tests and macOS cross-compilation do not enable macOS real-time health.
Approved native-broker scans run path resolution and traversal in a supervised
helper, with bounded request/output pipes and atomic admission of complete
results. Timed-out helpers cannot enqueue partial detections. Pending process
cleanup remains bounded and visible. All Linux/macOS quarantine and restore actions use
supervised workers, checksummed filesystem journals, independently retained bytes,
and atomic restore publication. Recovery reconciles committed effects without
replaying external mutations; previously issued receipts remain immutable. Pending native mutations pause all
quarantine/restore dispatch, including after a local backend change.
Linux protected quarantine hashes through the locally configured, excluded scanner
UID with read/search capability only. The intent pins that identity; the reader
inherits the mutation lock, keeping recovery excluded until it exits even if the
supervising worker dies. A new restore verifies retained private bytes independently
of the live scanner, so disabling protection does not strand managed evidence.
Original broker intents retain their existing digest and binding contract.
Portable Linux/macOS source verification uses exact file identity and the approved
hash inside the supervised worker. It refuses direct reads whenever a persistent
native broker binding exists, including after broker death. Completed older
quarantine records can be restored through the new journal without an original
operation journal. Incomplete legacy records still require local review.
Response roots must exclude the endpoint state directory; operations are capped
at 128 MiB per file and require the same filesystem as state. Windows now has a
journaled worker implementation with additional filesystem restrictions described
below; its native execution remains unverified.
Automatic macOS health now requires clean controls and exact delivered denial receipts for every root, with bounded synthetic diagnostics kept separate from malware automation. Approved scans recognize only exact owned health samples; matching bytes elsewhere remain detections. Native execution, signing, installer/controller validation, live health validation and protected-file response validation remain required.

## Native process and socket observations

New enrollments enable `"telemetry": {"enabled": true, "interval_secs": 30}` in the private endpoint configuration. Existing configurations without this field remain disabled; enable it locally to opt in. The interval accepts 1–3,600 seconds. Upgrade the server before endpoints: the protocol additions preserve existing event replay hashes, but older servers reject the new fields and event kinds.

The collector records process ID, parent ID, observed start times, executable path and OS user identity where available. Socket observations include TCP/UDP, local/remote addresses, state and owner PID where available. Process metadata is attached to a socket only if its identity is consistent across process snapshots bracketing the socket read. Command lines, environment variables, memory contents and packet payloads are not collected. Open a device's **Open device evidence** link to inspect original records; `/api/endpoints/{id}/events?before=EVIDENCE_ID` provides operator-authenticated pagination.

Linux reads procfs socket tables in the agent's network namespace. Windows uses the IP Helper owner-PID tables. macOS uses libproc process/descriptor information. Permissions, process churn and configured caps can leave gaps, which are exposed through collector health. These are sampled observations: short-lived activity may never appear, UDP peers are unknown, traffic byte counts are unknown, and there is no complete exec/exit history. Process start times have one-second resolution; the collector's persisted boot identity is a collection aid, not an OS attestation. An independent collection thread keeps sampling during remote actions, scans and stalled management requests; finite worker and queue budgets can still cause gaps.

Each capture admits at most 4,096 processes and 4,096 socket-owner records, with a 15-second worker deadline and 8 MiB accepted output budget. Changed observations and their comparison cursors commit atomically to SQLite. Up to 8,192 pending changes retain their original capture time across restart. Sampling continues while the pending queue has room, even when prior observations await delivery. A full queue pauses capture; an entire sample that does not fit is rejected without changing its comparison cursor or earlier retained observations. Disabling collection still delivers previously committed observations. Comparison keys missing from a sample are evicted without inferring an exit; a subsequent reappearance creates another observation. Telemetry uses at most 3,072 outbound slots to leave 1,024 available for other event types. HTTP batches are bounded to 64 records and 192 KiB of encoded JSON. Full admission fails visibly without advancing the comparison cursor. These finite budgets provide backpressure, not lossless observation of an indefinitely disconnected host.

Normalized observations retain endpoint-scoped identity and process context. Malware correlation uses the same endpoint and path within one hour, including sealed historical observations; it does not prove the observed process executed the detected file's content. Exact content hashes remain required for quarantine. The endpoint rules below correlate process lineage, socket ownership and observed user changes. Authentication feeds and kernel event collection remain separate work.

## Signed agent updates

The portal can propose, review, cancel and deliver signed releases to opted-in devices. A proposal can separately include automatic installation when local policy and a live controller permit it. Linux automatic installation has real-process and native-prevention verification; Windows has the implementation and cross-compilation checks, with native execution still pending. macOS automatic installation remains disabled pending native controller cleanup and replacement validation. The fleet rollout page schedules reviewed device groups and gates promotion on fresh post-installation health. Existing configurations keep updates disabled until a trusted release key and installation path are configured locally.

An offline signer creates a fresh private directory with `athernex-endpoint release-keygen NEW_PRIVATE_DIRECTORY`. Keep `release.pk8` off endpoints and the portal. The command prints the public key; `public-key.txt` contains the same value. A release is signed with:

```text
athernex-endpoint release-sign KEY_PK8 BINARY VERSION CHANNEL SEQUENCE EXPIRES_MS OUTPUT_JSON
```

The manifest binds the executable's SHA-256, byte count, platform/architecture, version, protocol, stable/preview channel, strictly increasing sequence and expiration. Validity is limited to 31 days. Ed25519 verification uses the locally pinned public key; a bundle cannot supply its own trust key. Signatures authenticate release authorization independently of HTTPS and package checksums. They do not replace Windows Authenticode or macOS signing/notarization.

Add this object to the endpoint's private `config.json`, using the actual public key and installed executable path:

```json
{
  "updates": {
    "managed": true,
    "automatic": false,
    "public_key": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
    "channel": "stable",
    "install_path": "/opt/athernex-endpoint/athernex-endpoint",
    "minimum_sequence": 0,
    "allow_unsigned_native": false
  }
}
```

`managed: true` permits reviewed portal delivery. Set `automatic: true` locally on Linux/Windows to permit proposals that explicitly include installation; staging-only proposals never trigger it. This also requires the installed controller. The portal cannot replace the local release key or enable this local permission. Keep managed delivery false for local-only updates. Restart the controller after changing policy. Upgrade the server before enabling this protocol extension.

Publish a signed manifest and its exact executable to a private catalog with:

```text
athernex-endpoint release-publish SIGNED_MANIFEST BINARY PUBLIC_KEY CATALOG_DIR
```

This verifies the release signature, validity, binary format, SHA-256 and byte count before publication. It stores only the public key, manifests and binaries. An existing catalog key cannot be silently replaced. Set the server's `ATHERNEX_ENDPOINT_RELEASES` to this directory; its default is `.athernex/endpoint-releases`. Keep catalog write access restricted to the release operator. The catalog admits 32 manifests. Retiring catalog files is an explicit operator action; do not remove files needed by pending deliveries.

Open **Endpoints → Manage signed updates** (`/endpoint-updates`). Device health shows its trusted-key fingerprint, channel, monotonic sequence floor and staged/installed release identities. Proposals require a recent heartbeat, the matching platform/key/channel and a newer sequence. Each proposal must be reviewed and expires after at most 15 minutes. Only an authenticated, active device assigned to an approved deployment can download its binary. Delivery uses 1 MiB chunks, at most 64 MiB total and a 120-second attempt budget. The server admits eight concurrent download bodies; a slow reader retains its slot until the body closes. The agent rechecks authorization immediately before staging, independently verifies the signature and all bytes, and persists its receipt before sending it. Three persisted attempts bound retries across process restarts; a failed delivery requires another operator proposal.

Cancellation/revocation prevents subsequent delivery/installation authorization. A staged proposal can be cancelled before installation starts. Once installation is authorized and begins, it must finish or recover; cancellation cannot undo executed changes. A late receipt remains attached to a cancelled/expired deployment, and changed receipt replays are rejected. A crash after staging is reconciled before polling new work, including after cancellation. The deployment ledger retains up to 2,048 records, admits 128 active proposals with one per device, and exposes 64-record cursor pagination at `/api/endpoint-updates?before=ROW`. Admission stops at the retention limit; an audited deployment-history retirement workflow remains unfinished. Backups include the deployment ledger. Release binaries and their catalog are separately managed release assets and must be backed up separately from the evidence database.

The sequence floor is exclusive. Each newly admitted release must exceed both the configured floor and the persisted high-water mark. A rollback does not reduce that mark. Identical staging retries are allowed; altered metadata or bytes at a reserved sequence are rejected. Windows/macOS additionally require their native signature checks unless the local policy explicitly permits unsigned development fixtures.

Use a separate trusted copy of the currently installed agent as the update controller. Stage the signed manifest and binary with `update-stage STATE_DIR SIGNED_RELEASE_JSON BINARY`; this is safe while the endpoint runs. Stop the controller service before invoking `update-apply STATE_DIR`. On older Linux installations, stop both the management and standalone protection services. Applying from the executable being replaced is refused. The updater checks both service locks, verifies the candidate again, checks its readiness response before and after replacement, and keeps a same-filesystem hard-link backup until confirmation. Readiness confirms startup and the expected version/protocol; it does not attest to detection coverage or complete runtime health. The filesystem must support hard links and atomic file replacement. On Unix, the installation file and its directory must belong to the updater and prohibit group/other writes. Windows installation directories must retain their administrator/SYSTEM ACLs.

After an interrupted update, run `update-recover STATE_DIR` from the separate trusted controller before restarting services. Recovery restores an unconfirmed replacement, removes partial candidates, preserves the sequence floor and is safe to repeat. Damaged backups or unexpected transaction paths fail closed for operator review. `update-status STATE_DIR` exposes the persisted state and last error. Ordinary management/protection startup refuses a pending replacement. During automatic verification, startup is permitted only for the exact candidate under its live controller and bounded trial token. The operator must restart services and check portal/protection health after applying or recovering; there is a protection gap during the maintenance window.

Automatic installation keeps the staging receipt and installation receipt separate. The controller rechecks server authorization and local policy before replacement, stops its children, preserves the confirmed executable, and starts a bounded runtime trial. Trial management can report health and deliver retained evidence/receipts; it cannot dispatch new remote actions or scheduled scans. Confirmation requires the expected executable/version, a successful server cycle, and verified active prevention when configured. The old executable is retained until these checks pass. A failed trial restores it and reserves the failed sequence. A controller restart recovers any unconfirmed transaction before starting normal services, including a crash after replacement but before the installation receipt. The portal retains immutable installed/rolled-back/refused receipts, including late results after expiry or revocation is reversed. These checks establish observed startup health, not detection coverage or indefinite service reliability.

The Linux and Windows installers create separate `athernex-launcher`, `athernex-controller` and agent copies. The systemd service or Windows startup task runs `athernex-launcher launch STATE_DIR CONTROLLER_BINARY AGENT_BINARY`. The stable launcher owns the controller and remains available to recover a controller that fails its trial. The controller owns management and configured native protection. macOS still starts its controller directly with `supervise STATE_DIR INSTALLED_BINARY`; automatic maintenance remains disabled there. Agent, controller and engine updates have separate signed histories. The launcher itself remains installer-maintained.

To enable controller maintenance, add `controller_path` to the locally trusted `updates` policy, for example `/opt/athernex-endpoint/athernex-controller`. It must differ from `install_path`. Agent and controller share the pinned release key, channel and configured sequence floor, but retain independent staged bytes, confirmed releases and monotonic histories. Configure this field only after upgrading to binaries that understand it. Stage with:

```text
athernex-endpoint controller-update-stage STATE_DIR SIGNED_RELEASE_JSON BINARY
athernex-endpoint controller-update-status STATE_DIR
```

For manual replacement, stop the launcher/controller service and use a separate trusted updater executable for `controller-update-apply STATE_DIR`. Apply and `controller-update-recover STATE_DIR` hold the real launcher, controller, management and configured protection locks. The shared update lock serializes both component ledgers. Neither component can update while the other has an interrupted transaction. Replacement authenticates the release and native signature, requires the controller readiness protocol, preserves the old executable and rolls back on failed readiness. An interrupted controller transaction prevents normal startup; recover it with the separate updater before restarting. Missing installation files, partial candidate copies and interruptions on either side of replacement are recoverable while the backup remains intact. Failed sequences remain reserved.

Manual replacement verifies executable readiness; the operator must restart the service and check management and prevention health. The unattended path below also requires a real runtime trial. A confirmed controller must subsequently start from its configured path with the exact signed bytes. The launcher verifies signed controller and agent bytes before executing them. Reinstallation cannot bypass either signed-release ledger: update both components to the installer's bytes first. Installation files/directories must prevent replacement by other users; these controls do not resist a hostile administrator. Native Windows/macOS runtime validation remains a release gate.

Manifests are limited to 8 KiB, executables to 64 MiB and the journal to 32 KiB. Staging keeps one candidate; replacement needs space for another copy on the installation filesystem while retaining the old file through a hard link. Linux/macOS bounded commands use an independent process watcher for owner/leader death and process-group cleanup. The macOS implementation still needs native execution before unattended updates can be claimed. Windows now creates managed and bounded subprocesses with an atomic job assignment, described below; its runtime tests also remain unexecuted in this workspace.

Windows subprocess ownership requires Windows 10 or Windows Server 2016 or newer. `CreateProcessW` receives both `PROC_THREAD_ATTRIBUTE_JOB_LIST` and an explicit standard-handle list. The job has kill-on-close enabled before creation, so there is no post-spawn assignment window. Creation failures do not fall back to unowned execution. Commands name an absolute `.exe`; shell/PowerShell automation selects its interpreter explicitly. UTF-16 argument encoding and case-insensitive environment edits preserve empty arguments, quoting, working directories, explicit environment clearing, and inherited drive-directory entries. See [Microsoft’s process attribute contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

Bounded Windows actions drain a pipe into bounded memory instead of an expanding temporary file. Root exit triggers descendant termination; success requires the root handle to be signaled and the job’s active-process count to reach zero. A short cleanup grace period is followed by a background reaper that retains handles and one of 16 capacity slots until cleanup is confirmed. Pending or uncertain cleanup prevents new local work and controller replacement admission. These checks cover processes created in the owned job; actions delegated through Windows services/WMI or privileged attempts to escape ownership are outside this lifecycle guarantee. See [Microsoft’s job-object behavior](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The Windows tests cover real process arguments/environment/handle inheritance, descendant cleanup after root exit or timeout, explicit stop, owner death, bounded output, exit code 259, failed creation, bounded worker input and the worker's actual creating parent. They are included in the existing Windows CI test step. Local cross-compilation/lint checks do **not** execute these tests.

Windows quarantine and restore now use the same journaled worker protocol as Linux/macOS. SQLite records intent before launch; the worker runs inside the owned job and returns a nonce-bound report. Recovery can finish retaining captured evidence or acknowledge an already-published restore, but cannot repeat a source capture or publish an unstarted restore. An issued receipt remains immutable; later reconciliation is recorded separately. Temporary worker input is limited to 64 KiB and passed through an explicit inherited standard-input handle, so a nonreading worker cannot block the parent while submitting the request.

Windows filesystem operations open each directory component relative to a pinned handle, reject reparse points and device/stream aliases, and compare the volume and full 128-bit file ID. Source capture renames the verified open file handle; restore publishes an independent private copy without overwriting an existing destination. New retained files and journals have explicit private ACLs. Existing state must also have a trusted owner and grants restricted to the service identity, SYSTEM and Administrators; unexpected permissions require operator review. See [Microsoft's handle-relative file-open contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) and [handle-based rename information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info).

This implementation currently requires local, same-volume storage with persistent ACLs and hard-link support. It refuses files containing alternate data streams rather than retaining only their unnamed stream. Directory metadata flushes must succeed before source capture; unsupported flush or cleanup operations remain errors or pending cleanup. The Windows fixtures cover filesystem interruption checkpoints, changed identities, old writers/hard links, restore conflicts, corrupt journals, scope/ACL boundaries and actual agent/worker recovery across the filesystem/database acknowledgement boundary. They have been cross-compiled and linked, **not executed on Windows**; neither native filesystem durability nor Windows malware prevention is validated by these builds.


`tools/verify_endpoint_update.py` generates temporary signing keys and disposable installation files, runs the updated binary through the real fleet journey, exercises signed-binary rejection, failed readiness rollback, process termination, preflight interruption and replay/expiry checks. It modifies no installed service. The native platform CI matrix includes this fixture; execution on Windows/macOS remains pending.

## Locally authorized unattended controller replacement

Linux and Windows support an exact local controller maintenance request. Set `updates.controller_automatic` to true, keep the trusted release key and `install_path`, and configure distinct absolute `controller_path` and `launcher_path` values. Linux defaults are `/opt/athernex-endpoint/athernex-controller` and `/opt/athernex-endpoint/athernex-launcher`. The default permission is false. Restart the service through the stable launcher after configuring this policy. Windows execution remains unverified; macOS rejects this opt-in.

Stage a signed candidate with `controller-update-stage`. Read its `staged_release_id` from `controller-update-status`, then authorize that exact release with a deadline at most 15 minutes away and within the signed validity window:

```text
athernex-endpoint controller-update-request STATE_DIR RELEASE_ID DEADLINE_MS
athernex-endpoint controller-maintenance-status STATE_DIR
athernex-endpoint controller-update-cancel STATE_DIR RELEASE_ID
```

Staging alone does not authorize replacement. A queued request may be cancelled before installation begins. Identical requests are idempotent and cannot extend the deadline. Requests retain one bounded local outcome. Portal-authorized controller requests also retain their exact deployment and immutable installation receipt, as described below.

The launcher rechecks local policy, signature, release identity, expiry and other maintenance before stopping the controller and its children. A busy maintenance lock defers admission while protection continues. The candidate receives an expiring ownership token. Its runtime trial freezes configuration and agent bytes, requires a real managed server cycle, and requires fresh active native protection when configured. New remote actions, scheduled scans, automatic agent installation and engine activation stay suspended during the trial. Confirmation preserves the independent agent and engine histories. Replacement causes a protection gap while the old processes stop and the candidate establishes blocking.

If the trial fails, the launcher stops its owned process tree, restores the previous controller, reserves the failed sequence and restarts normal supervision. If the launcher dies, owned controller and native descendants terminate; the OS service restart reconciles the automatic transaction before launching children. An interrupted agent replacement with a missing destination is also recovered before startup. Unrelated manual controller transactions require explicit recovery. Damaged journals, altered signed files or changed configuration stop recovery for review. A launcher lock excludes duplicate launchers and manual controller replacement throughout this lifecycle.

`tools/verify_controller_maintenance.py` exercises successful installation, runtime rollback, launcher death/restart, cancellation/expiry, manual-transaction refusal, signed-byte checks and missing-agent recovery in disposable local services. The separate Linux native-prevention fixture verifies controller replacement and launcher cleanup with real ClamAV blocking. Neither fixture establishes sustained fleet reliability or native Windows/macOS release readiness.

## Reviewed controller delivery

Set `updates.controller_managed` to true locally to accept portal-reviewed controller releases. This defaults to false and requires the pinned release key plus `controller_path`. It is independent of `updates.managed`, which authorizes agent delivery. Automatic controller installation additionally requires `controller_automatic`, `launcher_path` and a live stable launcher. The portal cannot enable these permissions or change the local trust key. Upgrade the server before enabling controller reporting on endpoints.

Publish the signed executable to the existing release catalog with `release-publish`. **Signed endpoint updates** (`/endpoint-updates`) shows separate Agent and Controller policy, sequence and installed/staged identities. Propose the release in the Controller section, optionally include automatic installation, then review the exact component, release and device before approval. A staging-only approval never authorizes a controller restart. The target component remains immutable for the entire deployment. Existing deployment records that omit a component continue to mean agent only.

Controller delivery uses the existing bounded, device-authenticated download channel, independently verifies the signed bytes, and stages them in the controller ledger. It preserves the agent executable and release history. Proposals and review require a fresh matching controller policy report; automatic admission also requires reported launcher ownership. A staged agent report cannot substitute for the exact staged controller release. Only one active agent/controller deployment is admitted per device. The shared 128-active/2,048-retained server budgets and cursor pagination apply to both components. Reviewed rollout groups support both agents and controllers, with independent component policy and preservation of the reported agent identity during controller replacement.

After the staging receipt is committed, the launcher checks local permission and server installation authorization before stopping services, then rechecks immediately before the trial. Cancellation before installation authorization prevents replacement. Once installation starts, the candidate must confirm or recover. The runtime health checks and rollback rules are the same as local controller maintenance. A failed or interrupted candidate cannot lower the controller's sequence floor.

The launcher journals the reviewed deployment and an immutable installed/rolled-back/refused receipt. Restart can recover the prior controller without server connectivity; management sends the retained result when connectivity returns. An unacknowledged result prevents an unrelated controller request from overwriting that journal. The endpoint marks delivery terminal before releasing the receipt for replacement. Late receipts remain attached to their original deployment, and changed replays are rejected. These are endpoint-reported observations, not independent attestation.

`tools/verify_controller_delivery.py` exercises the actual portal, server, launcher, controller and agent with temporary release keys. It verifies separate local permission, staging-only delivery, cancellation, runtime installation, failed-candidate rollback, simultaneous launcher/server loss, and exact receipt recovery after restart. Actual Linux ClamAV blocking is covered separately by `verify_native_protection.py`. Native Windows execution and macOS automatic maintenance remain release gates.

## Staged ClamAV engine replacement

Engine maintenance has a separate signed manifest and monotonic history. Add a locally trusted `engine_updates` object to `config.json` with `public_key` (64 hexadecimal characters), `root` (an absolute installation directory separate from state and protected roots), `channel` (`stable` or `preview`) and optionally `minimum_sequence`. `allow_unsigned_native` defaults to false; enable it only for development fixtures on platforms requiring native signatures. The updater must own the root and configuration, and their ancestors must prevent replacement by other users. Windows additionally requires private ACLs. The root belongs to one endpoint state. Library and certificate selection fields are written by activation, not configured independently.

Prepare a bundle from an already verified vendor prefix on the release machine:

```text
python3 tools/package_engine.py --prefix VERIFIED_PREFIX --output NEW_BUNDLE \
  --agent TRUSTED_ENDPOINT_BINARY --key PRIVATE_RELEASE_PK8 \
  --target linux-x86_64 --version 1.5.4 --channel stable \
  --sequence NEXT_SEQUENCE --expires-ms EXPIRATION_UNIX_MS
```

The packager copies runtime executables, shared libraries and database-verification certificates; it materializes file links into independent bytes and rejects directory links and files outside the prefix. It does not download or install a vendor package. `engine-sign` also accepts a custom content directory and roles JSON. The manifest binds every path, size, hash, executable role, library/certificate directory, target, version, channel, sequence and expiry under a separate Ed25519 signing domain. Limits are 128 files, 128 MiB per file, 512 MiB total and 64 KiB of manifest data. Native Windows/Mac signatures remain required unless local development policy permits otherwise. Universal Mach-O inputs must contain a valid slice for the selected target.

```text
athernex-endpoint engine-stage STATE_DIR NEW_BUNDLE/manifest.json NEW_BUNDLE/content
athernex-endpoint engine-status STATE_DIR
```

Staging is safe while protection runs: it creates a separate version tree and leaves active paths unchanged. Admission authenticates before copying, reserves the sequence and journals ownership before writing files. An interrupted copy can be retried with the identical manifest or removed using `engine-discard STATE_DIR`. Discard and rollback retain the sequence floor. The signed active release, one staged candidate and bounded retired history are kept separately from agent/controller releases.

Stop the launcher/controller service before `engine-apply STATE_DIR`. Activation excludes controller, management, protection and other update transactions. It checks native signatures and executable architecture, checks scanner/updater/daemon versions using a local configuration, distinguishes clean and custom-signature controls, and scans with the existing signature database. The Linux monitor is validated by its native trial because even its `--version` operation connects to a running daemon. Activation atomically selects the signed scanner, updater, daemon, Linux monitor, libraries and certificates while preserving endpoint credentials, policy and prevention scope. Inherited loader injection settings are cleared. On Windows/Mac, the separately installed native adapter remains unchanged.

When prevention is configured, a bounded owned trial must report fresh active native protection before confirmation. Failure stops the trial and restores the exact previous configuration. A killed updater leaves a journal that blocks normal startup; use `engine-recover STATE_DIR` before restarting. Recovery is idempotent, rechecks the prior signed tree, and refuses to overwrite unrelated configuration edits. The private journal contains the previous configuration; `engine-status` deliberately omits it. Configuration and signed bytes are checked again at subsequent startup.

Restart the controller after apply/recover and verify management plus `protection-status STATE_DIR --require-active`. The maintenance window has a protection gap. With services stopped, `engine-prune STATE_DIR` removes retired manifest-owned versions; it preserves active/staged versions and refuses altered files or unknown content. Prune is required before another stage once two retired versions accumulate. No package-manager scripts, global engine replacement or signature-database rollback are involved. Global AV reprovisioning is refused once this signed engine history exists.

The Linux fixture `tools/verify_engine_update.py --engine-prefix VERIFIED_PREFIX` passed eight real-engine lifecycle checks, including continued blocking during staging, selected private-library loading, native activation, controlled daemon failure, updater death and recovery, and tamper refusal. Test signatures and fault helpers are disposable. These checks establish observed activation and recovery behavior, not detection coverage or long-term reliability. Windows/Mac engine activation is implemented but has not been executed natively here.

### Controller-owned engine maintenance

Set `engine_updates.automatic` to true to permit the existing controller to activate an explicitly requested local engine release. The default is false. This option is available on Linux and Windows; native Windows execution is still required. Automatic Mac maintenance remains disabled pending native validation. Staging by itself does not authorize an interruption. After staging, authorize one exact release with a deadline no more than 15 minutes away and within the signed release's validity:

```text
athernex-endpoint engine-request STATE_DIR EXACT_STAGED_RELEASE_ID DEADLINE_UNIX_MS
athernex-endpoint engine-status STATE_DIR
```

The controller observes this local request independently of server connectivity. It rechecks local policy and expiry before stopping its managed children, then repeats admission under the shared maintenance lock. A busy update lock delays admission without stopping protection. The same owned native trial, signed-tree checks and configuration rollback used by manual maintenance apply. After confirmation or a clean rollback, the controller reloads configuration and starts management and protection. A request remains tied to its exact release; an identical retry cannot extend its deadline. Only one request is retained locally, alongside the engine's signed installed/staged/retired history. Fleet delivery adds the reviewed deployment and a durable receipt to this request, as described below.

`engine-cancel STATE_DIR EXACT_STAGED_RELEASE_ID` cancels a queued request and is safe to repeat. Cancellation cannot undo an activation that already began. While a request is pending, other engine staging/discard/manual-apply operations are refused. A refused or cancelled request leaves staged content available for an explicit new authorization or discard.

If the controller dies after journaling its activation, its owned trial processes terminate. On restart, it restores the previous configuration before launching normal children, preserving the failed sequence and a `rolled_back` request result. Recovery remains valid after the request expires and never retries the failed installation. A manually interrupted engine transaction still requires manual recovery. Unrelated configuration changes or corrupted journals stop automatic recovery for review; they are not overwritten. `engine-status` includes the request's release, deadline, phase, time and bounded outcome detail without exposing configuration credentials.

Run `tools/verify_engine_update.py --automatic --engine-prefix VERIFIED_PREFIX` for the controller-owned lifecycle fixture. Native Windows/Mac release validation remains a separate requirement.

### Reviewed fleet engine delivery

Upgrade the server and endpoint before enabling fleet engine delivery. Set `engine_updates.managed` locally to permit signed downloads, and `engine_updates.automatic` to permit reviewed installation under the live controller. Keep the existing pinned engine public key and private installation root. Publish a verified signed bundle to the server's engine catalog:

```text
athernex-endpoint engine-publish MANIFEST CONTENT_DIR PUBLIC_KEY_FILE RELEASE_CATALOG/engines
```

Set `ATHERNEX_ENDPOINT_RELEASES` to `RELEASE_CATALOG` on the server. **Engine updates** (`/engine-updates`) supports staging-only proposals, separately approved installation and canary plans. The device review exposes the exact deployment, target, sequence and approval hash. Cancellation remains available after approval until installation is authorized. The server cannot enable local managed/automatic policy or replace the pinned key. Agent, controller and engine maintenance share exclusion and reservations.

The endpoint downloads only manifest-owned files within their signed size/hash limits and stages them through the existing signed-tree admission. A staging receipt never implies installation. Installation authorization is rechecked against the exact deployment before the controller interrupts services and again before activation. Local policy and expiry are checked at both boundaries. A local request for the same release is not adopted as a fleet result.

Installation, rollback, refusal and cancellation results are written into the controller's durable engine request before delivery. Recovery of an already interrupted activation does not require a reachable server and remains valid after expiry. Unacknowledged results block further engine maintenance and agent/controller replacement while allowing the confirmed protection service to restart. The client commits the exact server receipt and local delivery record before releasing that hold. Receipt replay is immutable, including refused staging; disabling future managed delivery does not suppress an already stored result. Older unbound local requests remain local and are not treated as proof that a new fleet deployment ran.

Run `tools/verify_engine_update.py --fleet --agent PATH_TO_ENDPOINT --server PATH_TO_SIEM --engine-prefix VERIFIED_PREFIX` for the real-ClamAV delivery, rollback and offline recovery fixture. `tools/verify_engine_ui.cjs` separately verifies populated browser review/receipt controls using controlled health and results; it does not install an engine. Group promotion combines fresh endpoint and engine health with receipts and observed health windows; portable group tests are distinct from real multi-device engine installation validation.

Use `--rollout` in place of `--fleet` to exercise two independent endpoint states and controllers with native ClamAV in one disposable Linux container. The scenario checks actual installation receipts, 60-second observations from both health streams, control-plane restart, private-library selection, native blocking and failed-canary rollback with no later dispatch. It uses a 3 GiB container memory limit and 2 GiB fixture tmpfs, with no network beyond container loopback. This tests two endpoint instances on one kernel; separate-host fleet reliability and native Windows/macOS release validation require their own environments.

## Fleet rollout scheduling and promotion

Open **Signed endpoint updates → Manage fleet rollouts** (`/endpoint-rollouts`). Select Agent or Controller and one signed release, name the exact devices in its first and later groups, choose a start/deadline window and observation duration, then review and approve the immutable plan. Approval includes automatic installation. It binds the component, release, public key, device identities/order, group sizes, timing and required health. The server cannot add devices or change the component of an approved plan. A separate per-device deployment is created only when its group becomes eligible; its authorization expires within 15 minutes and no later than the rollout deadline. Existing agent plans retain their original serialized approval hashes.

Every target must already permit managed automatic installation for the selected component, match the release platform/key/channel/sequence, and report healthy. Agent installation requires a live controller; controller installation requires a live stable launcher and the separate local `controller_managed` and `controller_automatic` permissions. Each component uses its own release history and sequence floor. The rollout preserves each target's configured prevention scope (backend, watched roots and scanner identity), collection and signature availability. Existing health errors hold admission. A successful installation receipt starts a wait for new health reports; it does not promote the next group. Fresh reports must name the exact installed release in the selected component's health, show its live supervisor, and preserve the required protection and collection health. Agent rollouts also require the new agent version. Controller plans bind the agent version and installed-release identity observed at proposal; those values must remain unchanged at approval, dispatch and throughout post-installation observation. At least two reports must span the full observation duration. More than 120 seconds between healthy reports resets that device's observation window. Stale installed-device health, changed protection scope or agent identity, dropped native detections, failed collection, rollback or a refused/expired/cancelled deployment fails the rollout and cancels work that has not started installation. Previously installed groups remain monitored until the entire rollout completes. These are endpoint-reported health observations, not independent device attestation or detection-coverage measurements.

Pause prevents new downloads and installation starts and resets observation windows. Resume keeps the exact reviewed plan and existing deployment deadlines; it cannot silently renew an expired authorization. Cancellation/failure stops future groups and preserves immutable receipts. An installation already authorized to start must finish or recover, and an already confirmed release remains installed. Recover a failed device locally and use a newly reviewed higher-sequence release when remediation is required; there is no automatic downgrade of confirmed devices. The server persists group assignments, health observations and dispatch IDs transactionally, so restart cannot duplicate a deployment or count downtime alone as healthy observation.

Limits are 64 devices per rollout, 1–16 devices per group, 60–3,600 seconds observation, a window of at most seven days within signed-release validity, eight active rollouts and 32 retained rollout records. Rollouts reserve their future share of the existing 2,048 retained deployment budget; at most 128 deployments can be active overall. An endpoint cannot simultaneously belong to another active rollout or receive separately proposed maintenance. Capacity exhaustion holds new work without deleting receipts. Active installations remain reserved until their result arrives even if their rollout expires. Records are available to authenticated operators at `/api/endpoint-rollouts` and `/api/endpoint-rollouts/{id}`; the detail export contains the exact plan/hash and per-device progress. The operational server advances groups in its normal ticker, without requiring a browser to remain open.

## Continuous sampling and endpoint detections

The `run` command owns an independent telemetry thread with a separate SQLite
connection. A stalled server request, long scan or approved automation no longer
blocks the sampling scheduler. Both connections use durable transactions and
atomic queue admission. The worker is joined before the agent releases its state
lock or hands control to the updater. `run --once` retains synchronous collection.
Configure `telemetry.interval_secs` from 1 to 3,600 seconds (default: 30). A capture
can take up to 15 seconds; collection is bounded sampling, not a lossless execution
trace. Short-lived processes and sockets can still be missed. The queue remains
finite; a full durable queue pauses new sampling instead of silently dropping
acknowledged evidence. Stale collection and pending delivery appear in health.

While a bounded sample is running, health retains the last completed result and
its original success timestamp. Starting a sample does not itself signal a
collection failure or renew that success time. An unfinished capture without its
live worker, a capture exceeding 30 seconds, a stale result or real delivery backlog
remains unhealthy. Successful snapshot admission publishes health and its initial
queue transfer atomically, so rollout observations do not see an intermediate
queue that is still being committed.

Three additional rules consume the preserved typed observations:

| Rule | Evidence and meaning |
| --- | --- |
| AX-006 | An interpreter names a browser/document application as its parent, with matching device, boot, PID and process start time. This is an investigation signal; legitimate automation can match. |
| AX-007 | An interpreter process record exactly matches the metadata attached to an established TCP socket with a non-local peer. The evidence does not establish direction, transferred bytes or malicious intent. |
| AX-008 | The same observed device, boot, PID, start time and executable changed from a non-system user to root/SYSTEM. Authorized privilege changes can match; the mechanism is not inferred. |

Correlations use a two-minute window and at most 32 neighbors per graph lookup.
Late process/parent delivery revisits eligible retained observations. A case and
its replay claim commit with the endpoint event; a failed commit acknowledges
nothing. Claims survive restart and finding-window eviction while their case is
retained, preventing repeated alerts for the same process/rule. Rule controls
apply to new matches. These rules create analyst investigations and do not invoke
the malware quarantine playbook. Broader native event subscriptions, authentication
feeds and measured detection/false-positive coverage remain necessary for full XDR.

The real-process regression in `tests/continuous_telemetry.rs` withholds the
server's heartbeat response, creates a process after that request begins, and
verifies that its observation is saved and survives agent termination. Additional
tests cover queue contention, restart, stale collection, out-of-order delivery,
cross-device/boot/PID exclusion, rule controls, false-positive boundaries and
transaction failure.

### Optional Linux kernel process events

Enable `"linux_process_events": true` alongside `"enabled": true` in the private
`telemetry` configuration to subscribe to Linux CN_PROC events. The default stays
off. Upgrade the server first; older servers reject the new typed event kind.
This requires `CONFIG_CONNECTOR` and `CONFIG_PROC_EVENTS`, access to the connector,
and the initial PID, user and network namespaces. Kernel and local security policy
may require `CAP_NET_ADMIN`. An unavailable subscription fails startup explicitly.
`run --once` cannot be used with this continuous collector.
Restart the agent after changing this local collection policy.

The independent worker preserves fork, exec, exit, user/group ID, session, ptrace,
name and core-dump notifications. It records the kernel PID/TID, per-CPU sequence,
monotonic timestamp, boot identity and subscription identity. Wall timestamps are
estimated from receipt time; the original monotonic value remains available.
Name changes preserve the original 16 bytes as hex. These records do not establish
an executable path or command line, and are never enriched by looking up a PID
that may already have exited or been reused. Credential/session changes are not
login/authentication records. The existing snapshot rules retain their stricter
process-identity requirements. The [kernel ABI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/cn_proc.h)
and [sender implementation](https://github.com/torvalds/linux/blob/master/drivers/connector/cn_proc.c)
define the underlying observations.

Events enter the existing bounded durable queues transactionally and continue
arriving while HTTP requests stall. A full queue preserves older evidence and
counts rejected new records. Socket overflow, sequence discontinuities and an
unclean subscription restart remain visible as coverage gaps across restarts.
Loss notifications count detected gaps, not the exact number of missing kernel
events. No subscription can recover events from before it started or while it
was stopped; each start emits a durable boundary record. A clean restart starts
a new stream and exposes its unobserved interval. Historical loss stays degraded;
there is no command to erase or acknowledge those counters in this release.

The portal displays native subscription freshness, event/drop/loss counts and
typed event details. Raw operator-authenticated exports preserve the originals
through delivery and replay. Rollouts approved with native collection require
fresh, active, gap-free native health throughout promotion; turning the collector
off or losing events cannot silently satisfy that approval.

The native gate creates short-lived children during stalled delivery, kills and
restarts an actual agent, verifies exact records through authenticated server
delivery/reopen/replay, and deliberately overflows only its own receive socket.
It requires a compatible running Linux kernel and is separate from portable
workspace tests:

```sh
cargo test --locked -p athernex-endpoint --lib --test continuous_telemetry --no-run --message-format=json > /tmp/process-event-tests.jsonl
python3 tools/verify_process_events.py --manifest /tmp/process-event-tests.jsonl --agent target/release/athernex-endpoint --image athernex-native-protection-fixture:local
```

The optional existing test image shares host PID/network namespaces for CN_PROC
and uses a read-only filesystem plus private bounded temporary storage. It makes
no global audit, tracing or socket-buffer changes. Omit `--image` to use the current
user's permitted local subscription instead. These checks do not establish
lossless capture under sustained load or complete XDR detection coverage.

### Optional Linux network tracker events

Set `"linux_network_events": true` alongside `"enabled": true` in the private
`telemetry` configuration, upgrade the server first, and restart the agent.
The default is off. `run --once` is refused for this continuous collector.
The kernel must support Netfilter connection tracking, event delivery and
`nfnetlink_hook` introspection. The service needs permission to subscribe and
inspect hooks (normally `CAP_NET_ADMIN` in its network namespace), with
`nf_conntrack_events` set to 1 or 2 by existing system policy. The agent does not
install firewall rules or change sysctls.

Subscribing alone does not establish a working source. Startup checks tracking
and confirmation hooks for IPv4 and IPv6 and requires a complete set for at least
one family. Read-only checks repeat every five seconds. Missing inspection,
disabled events or a changed family set stops the worker and records a gap.
Health reports the checked families and network namespace; it does not claim
coverage in other namespaces. Existing NOTRACK policy and other tracking bypasses
can exclude traffic even when hooks are present. Deploy this only with a reviewed
tracking policy; hook inspection is an availability check, not a firewall audit.

Records preserve TCP/UDP tracker creation, updates and removal, original and
reply tuples (which may differ under NAT), tracker ID, status, available zones,
mark, timeout, TCP state, cumulative counters and tracker timestamps. Unknown
attributes are not exported; unsupported transport protocols are counted and
skipped. IDs can be reused, so durable observation identity includes the boot,
subscription, namespace and local receipt sequence. The outer timestamp and
monotonic receipt time describe collection, not an inferred packet timestamp.
Originating netlink ports are not process IDs. These observations establish no
process owner or firewall verdict, and tracker removal does not establish socket
close. Cumulative counters remain in the original evidence; normalized byte
deltas stay zero so repeated updates cannot inflate transfer-volume detections.
The [kernel conntrack specification](https://docs.kernel.org/netlink/specs/conntrack.html)
and [sysctl documentation](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)
describe event fields, automatic event extensions and optional accounting.

Collection continues independently of HTTP requests and commits to the existing
bounded durable queues. Queue exhaustion preserves older records and counts
rejected observations. Kernel socket overflow, source failure and unclean agent
restart leave sticky loss indicators; loss notifications do not count every
missing event. Each subscription emits its own boundary. Clean shutdown still
leaves an unobserved interval, and prior tracker entries may lack event extensions
in automatic mode. There is no backlog replay from the kernel and no loss-counter
reset command. Portal evidence/export and rollout gates preserve these limits;
an approved native collector cannot disappear or report stale/lost coverage and
still satisfy promotion.

The explicit native gate runs three tests in separate disposable containers with
private PID/network namespaces, read-only root filesystems and bounded temporary
storage. It checks missing/removed hooks, real socket overflow, short-lived IPv4
and IPv6 TCP/UDP flows during stalled actual-agent HTTP, deliberate tracker
removal, agent crash/restart, authenticated delivery, original export and replay.
Only the fixture enables tracking/accounting in its private namespace. The host
firewall, networking and sysctls are not changed.

```sh
cargo build --locked --release -p athernex-endpoint -p athernex-siem
cargo test --locked -p athernex-endpoint --lib --no-run --message-format=json > /tmp/network-event-tests.jsonl
docker build -t athernex-native-network-fixture:local infrastructure/endpoint/network-tests
python3 tools/verify_network_events.py --manifest /tmp/network-event-tests.jsonl --agent target/release/athernex-endpoint
```

These bounded fixtures do not establish sustained-load, multi-host or complete
network/detection coverage. This source supplements the existing process/socket
snapshots; it does not supply process attribution for those snapshots.

### Optional Linux authentication journal

Set `"linux_authentication": true` in the private `telemetry` configuration,
alongside `"enabled": true`, then restart the agent. This is disabled by default
and requires root access to the local default journal namespace, libsystemd 254
or later, and a responsive journald control socket. Upgrade the server before
enabling it. `run --once` is not supported with native event collectors.

The reader retains supported OpenSSH authentication allow/deny reports, default
English sudo password-failure summaries, and `pam_unix(...:auth)` failure reports
from the known SSH, sudo, login and su executables. It uses journal-supplied executable, PID and UID fields rather than
the caller-supplied syslog identifier. A key lookup, opened session or authorized
sudo command is not treated as a completed authentication. Parsing is deliberately
limited to the supported message forms; ambiguous addresses, duplicate PAM fields
and unsupported authentication suffixes are rejected and counted. Certificate
details, translated/custom PAM messages and other identity providers require
additional parsers and native validation.

For sudo, the invoking account before the report separator is the claimed
account; `USER=` names the requested target and is not substituted for it.
An aggregate password-failure summary contributes one completed service denial,
regardless of the reported attempt count. Command authorization, `NOPASSWD`,
policy refusal and PAM fallback do not establish a fresh authentication result.
The local journal collector uses the same envelope parser: password failures
containing `COMMAND=` are denials, and rejection-like text inside command
arguments cannot change a command authorization into a policy denial. A missing
terminal field is supported. Translated/custom reasons, continuation records,
unknown layouts and incomplete envelopes are not guessed. These distinctions
follow [sudo's authentication-failure logging](https://github.com/sudo-project/sudo/blob/main/plugins/sudoers/logging.c).

If `_EXE` is unavailable, recognizable authentication-shaped reports from a
supported process-name hint increment the persistent rejected-record count and
degrade coverage. The hint never creates an authentication fact or substitutes
for executable provenance. A known unrelated executable cannot become a trusted
producer by using a syslog tag. This preserves the distinction between
[journal-supplied process fields and client-supplied fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html).

Each retained observation includes its original message, journal cursor,
sequence identity/number, machine/boot identity and timestamp. The claimed account
remains separate from the reporter's UID and from process identity. Claims are
scoped to the reporting endpoint; matching account names on different devices do
not merge. Eight service-reported denials for one such account within two minutes feed the
existing AX-001 investigation rule. Legitimate failed logins can meet that rule;
these observations do not authorize automatic quarantine or establish a measured
production false-positive rate. The endpoint evidence page and authenticated
exports retain the original reports, including after source-journal rotation.

A `pam_unix` failure describes one module's result. A later module in the same
PAM stack may still accept the login. These records retain their original module
failure outcome, but normalize as observations and do not count toward the denied
authentication threshold. The portal labels their scope explicitly. The same
rule applies to the local SIEM journal collector. Completed OpenSSH reports
supply the service outcome, as do supported sudo password-failure summaries,
so a PAM failure and the accompanying service denial
cannot count twice. This follows the [PAM stack control semantics](https://raw.githubusercontent.com/linux-pam/linux-pam/master/doc/man/pam.conf-syntax.xml).
The correction applies to newly ingested observations; existing normalized
ledger records and investigation evidence are not rewritten. Review any
historical findings affected by the earlier mapping.

First enablement starts at the current journal tail and records that boundary;
it does not silently import earlier history. Later starts resume at the exact
durable cursor. Records, cursor and health counters commit together. If delivery
fills the durable queue, reading pauses without advancing that cursor or deleting
older evidence. Retained journal entries can therefore be replayed after an agent
crash, including events written while it was stopped. If retention removes the
cursor, collection resumes from available entries with a persistent coverage gap.
Sequence discontinuities, journal-reported suppression, rejected candidate
reports and writer failures also keep coverage incomplete. Gap notifications
are not an exact count of lost authentications, and no counter-reset command is
provided in this release.

A bounded, read-only `org.varlink.service.GetInfo` request checks the root-owned
journal writer; readable old files alone cannot report healthy collection. Health
also exposes catch-up and queue pressure. Rollouts approved with authentication
collection require that coverage to remain present, fresh and healthy. The agent
does not change host journal retention, rate limits, audit rules or service
configuration. Source-side filtering, unsupported producers and events outside
the retained collection interval remain coverage limits. This is endpoint-reported
provenance, not attestation against a compromised administrator.

The cursor and sequence behavior follows the native
[cursor contract](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_get_cursor.html)
and [sequence API](https://www.freedesktop.org/software/systemd/man/latest/sd_journal_get_seqnum.html).
The separate native fixture creates private SSH keys and accounts, runs isolated
SSH and journald processes, and uses bounded temporary filesystems. It tests real
allow/deny attempts, stalled delivery, replay during agent downtime, journal
retention loss, an unresponsive writer, authenticated exports and detection. A
third fixture exercises real PAM module failure followed by service denial or
successful fallback, and full-queue cursor recovery across restart:

```sh
docker build -t athernex-native-auth-fixture:local infrastructure/endpoint/auth-tests
cargo test --locked -p athernex-endpoint --lib --test authentication --no-run --message-format=json > /tmp/authentication-tests.jsonl
python3 tools/verify_auth_events.py --manifest /tmp/authentication-tests.jsonl --agent target/release/athernex-endpoint
```

The same native gates also run against the Debian 13 fixture:

```sh
docker build -t athernex-native-auth-fixture:debian13 -f infrastructure/endpoint/auth-tests/debian13.Dockerfile infrastructure/endpoint/auth-tests
python3 tools/verify_auth_events.py --manifest /tmp/authentication-tests.jsonl --agent target/release/athernex-endpoint --image athernex-native-auth-fixture:debian13
python3 tools/verify_auth_events.py --manifest /tmp/authentication-tests.jsonl --agent target/release/athernex-endpoint --image athernex-native-auth-fixture:debian13 --missing-provenance
```

Debian 13 acceptance exercised OpenSSH 10.0p1, PAM 1.7, sudo 1.9.16 and
systemd 257. All five native checks passed with the existing producer rules;
the observed terminal SSH reports came from `/usr/lib/openssh/sshd-session`.
The fixture explicitly disables supported OpenSSH source penalties in its two
private SSH configurations and verifies the effective setting, so its deliberate
denial burst produces authentication reports instead of pre-authentication
connection drops. Older servers retain their existing configuration. Exact-original,
queue, restart, retention, detection and missing-provenance assertions remain
required. These isolated containers share the host kernel; this evidence does
not establish separate-host reliability, every PAM provider, localized messages
or production detection quality.

### Optional Windows Security logons

Set `"windows_authentication": true` alongside `"enabled": true` in the private
`telemetry` configuration, upgrade the server first, and restart the Windows
agent. The default is off; `run --once` is refused. The service needs access to the
local Security channel and audit-policy inspection. Security reads temporarily
enable an already-held `SeSecurityPrivilege` on a duplicate of the thread's
effective token, then restore its prior impersonation. Accounts without that
privilege still require existing audit-object/channel access. Production collection only
reads policy: Logon success/failure and Account Lockout failure auditing must
already be enabled. Disabled or uninspectable policy, per-user exclusions and a
disabled/full channel make coverage incomplete.

The collector preserves original XML for Security provider event 4624 versions
0–2 and event 4625 version 0, with bounded parsing and explicit rejection of
unsupported logon types or malformed candidate records. Target account/domain/SID,
reported caller PID/image and source address remain separate fields. A successful
type 9 NewCredentials session normalizes as an observation because it does not
establish outbound authentication; cached logons do not establish a fresh domain
controller check. See Microsoft's [4624 field contract](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
and [4625 field contract](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).
The server neither infers a process lifetime from a caller PID nor merges the
same account spelling across devices or reported domains. Eight denied reports
for one such account within two minutes feed AX-001; originals remain available
to authenticated operators and exports.

First enablement records the current tail as its collection boundary. Subsequent
starts resume from a durable bookmark bound to the log's creation time and a hash
of the native System identity at that position. Every Security position is read
so unrelated events do not create apparent sequence gaps; unrelated payloads are
not retained. Original reports, bookmark and health commit together. Full queues
pause reading without advancing the bookmark. Missing/reused positions, sequence
gaps, supported source-loss/policy-change markers and rejected candidate records
leave persistent incomplete coverage. The portal reports this source separately
from Linux authentication, and rollout plans require configured Windows coverage
to remain present, fresh and healthy. Source-side omissions and a compromised
administrator remain outside this evidence's guarantees.

The independent `windows-authentication` CI job runs an explicitly disposable
LocalSystem/session-zero component fixture. It creates one owned account and
temporarily configures the two audit subcategories, with checked account deletion
and exact policy restoration. It exercises real successful/failed logons, stalled
HTTP, full queues, forced collector-process termination, replay, authenticated
original export, controlled AX-001 evidence and an observed policy gap. It checks
anchor mismatch without clearing the host Security log. This is not the full SCM
agent lifecycle or a measured production coverage result. The gate must pass on its source commit before native behavior is considered
validated. Uploaded artifacts contain only suite-bound status
and executable hashes; account details and event XML stay on the disposable host.

### Windows process source experiment

The independent `windows-process-source` job is a test-only ETW source experiment
on a disposable LocalSystem/session-zero host. It creates one named system logger
with a fresh ownership GUID and requires actual Start/End events for eight owned
child processes. Native TDH metadata must supply exact target PID, parent,
session, exit status and process-key fields. Rundown cannot satisfy the lifecycle
check. The fixture also requires zero source/callback losses, unchanged token
state, removal of the owned session and completion of its consumer thread.

This gate establishes source behavior only when it passes; it does not validate
continuous Windows process collection, durable delivery, rollout coverage or PID
reuse tracking. The public `process-source-validation.json` keeps
`proof_scope: "source_only"` and `production_readiness: false`. It contains fixed
status/failure categories and structural schema fingerprints. Raw events,
command lines, account data and kernel addresses stay on the disposable VM;
only the public report and its input manifest are uploaded.

### Windows process-event collection

The separate `windows_process_events` telemetry option defaults to false. Enable
it alongside `telemetry.enabled` only on Windows, after upgrading the server;
`run --once` is refused. The collector uses a private named ETW system logger,
with durable ownership intent recorded before session creation. Restart recovery
checks the recorded session identity and original owner's process creation time
before reclaiming an orphan. It refuses a foreign session, a live owner or an
impersonated caller. It does not change token privileges or configure the global
kernel logger.

Start, end, rundown start, rundown end, defunct and termination reports remain
distinct observations. The full lifecycle parser accepts bounded classic process
versions 2–4 with explicit 32/64-bit layout flags. The separate opcode 11/version
2 termination decoder requires an exact four-byte reported PID; parent, session,
exit status, process key, image and command line remain explicitly absent. Existing
full lifecycle reports retain their original numeric/string wire fields. Unknown
layouts and malformed records become visible rejection counters.

The native source experiment has exercised version 4/64-bit Start/End records.
Native diagnostics have also observed an opcode 11/version 2/64-bit TDH schema
with one PID property. Exact termination-payload length and controlled-target
delivery still require the separate native acceptance gate below; those diagnostics
alone do not validate the new decoder. Other layouts have portable synthetic
coverage only.
Reported PID, parent PID, SID, image bytes and process-object key do not establish
verified executable identity, ancestry or a process incarnation. ANSI image bytes
remain hexadecimal bytes rather than a guessed path or code-page conversion.

Each admitted original preserves semantic ETW header/context fields, extended
data and payload bytes, bound to a collector stream and receipt ordinal. Native
pointers and padding are excluded; the payload itself can contain kernel
addresses, command lines and account information. Original export therefore
requires authenticated operator access. A bracketed local QPC/UTC sample provides
a qualified timestamp estimate. Its displayed uncertainty describes sampling
and quantization, not wall-clock correction, drift or cross-host accuracy.

Originals and health commit together in the local durable queue. Committed events
retain their IDs through delivery retries and restart; live ETW has no source
replay cursor. Restart intervals, native loss counters, callback drops, rejected
records and full-queue drops leave persistent incomplete coverage. Windows process
health appears separately from Linux process events, and configured rollout
requirements for agents, controllers and engines require that source to remain
present, fresh and healthy.

The independent `windows-process-events` CI gate exercises the release agent as
well as collector components on a disposable LocalSystem/session-zero worker.
It requires actual controlled lifecycles, rundown and a separate PID-only
termination observation in both the component and release-agent phases, native TDH agreement with
the portable decoder for PID, parent, session, exit status, process key and pointer
width, stalled HTTP, bounded queue loss, forced agent termination,
orphan recovery, committed-original replay, authenticated export, portal coverage,
server restart and checked cleanup. These requirements describe the gate; native
acceptance is established only by a successful run on the exact source revision.
Its public report keeps `proof_scope: "component_and_agent"` and
`production_readiness: false`. Only fixed result categories, numeric API diagnostics,
bounded structural schema metadata and the exact input hashes are uploaded. Raw originals, worker reports, commands
and logs remain on the disposable VM. This fixture does not establish sustained
fleet reliability, lossless coverage or production signing and tamper resistance.

## Storage lifecycle and recovery

`/storage` shows disk headroom, live usage, budgets and sealed segments. The default live ledger ceiling is now 64 MiB, configurable from 16–1,024 MiB. Up to eight segments are attached. The default seal threshold is 8,192 live references and minimum disk reserve is 64 MiB. Limits apply independently; evidence retention remains finite.

Before admitting a batch, the server checks capacity. Cold evidence is copied into a separate SQLite segment, verified, synced, and renamed before the live transaction records the segment and removes its copied rows. Hot/context evidence stays live. Each segment carries complete evidence objects, graph links and endpoint payloads. Queries merge bounded candidates from each indexed segment. Promotion can restore a small reference/graph entry into the live ledger. Dictionary reclamation keeps active labels while sealed evidence retains its own label meanings. Schema 5 prevents older binaries from reading this new contract.

Segment hashes are checked at startup and evidence hashes during reconstruction. Missing/corrupt segments fail closed. No segment is silently deleted. At the segment limit, further sealing refuses ingestion with retry information; operators must make an explicit capacity/retention decision. Individual segment exports do not include all control-plane state. A complete backup includes the live database, all referenced segments and a checksum manifest:

```sh
systemctl --user stop athernex-siem
target/release/athernex-siem --db /private/state/siem.sqlite3 --backup-dir /private/backups/new-backup
target/release/athernex-siem --verify-backup /private/backups/new-backup
systemctl --user start athernex-siem
```

Restore by copying `ledger.sqlite3` and its adjacent `ledger.sqlite3.segments` directory into a new private state directory, then start with `--db` pointing to that copy. Preserve the verified backup unchanged. The database contains operational credentials; protect the whole backup. Hashes provide corruption detection, not independent WORM/audit anchoring.

## Verification and remaining release gates

```sh
make check-endpoint
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --locked -p athernex-siem -p athernex-endpoint
python3 tools/verify_endpoint_fleet.py
python3 tools/verify_endpoint_update.py
python3 tools/verify_endpoint_update.py --component controller
python3 tools/verify_automatic_update.py  # Linux/Windows; uses disposable processes
python3 tools/verify_controller_maintenance.py  # Stable launcher, runtime trial and recovery
python3 tools/verify_controller_delivery.py  # Reviewed transport and durable installation receipts
python3 tools/verify_endpoint_rollout.py  # Real two-device rollout and failed canary
```

The real-process fixture downloads an installer from the portal, verifies native capture of its own process and loopback socket, runs its agent, enrolls it, completes approved inventory, kills/restarts the server and verifies result recovery and a complete backup. Its agent policy disables general host collection; all recorded fixtures are controlled test data. `tests/endpoint_loop.rs` exercises actual TCP transport, byte-bounded delivery of large valid events and, when `/usr/bin/clamscan` exists, a real scan using a tiny benign custom-signature database. No global signatures, host files or installed services are modified by those tests. Telemetry tests cover atomic admission, restart-safe backlog, PID/boot changes, device-scoped correlation, operator-only views and original-payload case export. Storage tests cover seal/restart, historical promotion/replay, corruption rejection, retryable quota backpressure, high-cardinality dictionary recycling and backup restoration. The browser fixture `tools/verify_endpoint_ui.cjs` checks an actual installer download, device evidence navigation, operator review/result controls and desktop/mobile layouts; set `PLAYWRIGHT_MODULE_PATH` and `CHROME_BIN` for a local Playwright/Chrome installation.

The Linux prevention fixture uses the pinned upstream engine inside a disposable, network-isolated Docker container. It monitors only `/fixture` test data, never host folders. The added `linux-prevention` CI job runs it independently of the native platform matrix. To reproduce locally:

```sh
cargo build --locked --release -p athernex-endpoint -p athernex-siem
python3 tools/prepare_native_protection_fixture.py --output /tmp/athernex-native-av
docker build -t athernex-native-protection-fixture:local infrastructure/endpoint/tests
python3 tools/verify_native_protection.py --engine-prefix /tmp/athernex-native-av/engine/usr/local
```

Full XDR/AV replacement still requires Windows/macOS native prevention and cross-platform tamper protection, continuous process/network/identity collectors and cross-source detections, measured detection/false-positive coverage, sustained fleet reliability across separate hosts, native Windows/macOS installation and recovery testing, and production signing/notarization. The Kafka rack-orchestration bridge and Crustacian's legacy batch-envelope adapter remain separate integrations. These are tracked as unfinished work, not implied by the available installer buttons.

### Local verification, 2026-10-23/24

- The complete workspace suite passed 267 tests, including 47 endpoint/protocol unit tests, eleven actual endpoint-process response tests, 54 native-adapter transport/policy/broker/mutation/service/health tests and three actual operation/preparation process tests, six deployment integration tests, seven fleet rollout integration tests and the native receipt TCP/SOAR integration test. Coverage includes operator/CSRF authorization, device-scoped downloads, live response capacity, tampered binaries, bounded retries, cancelled-delivery recovery, immutable staging/installation receipts, separate installation approval and installer protection of signed release history. The separate telemetry process fixture also passed; its child helper is invoked explicitly and is otherwise ignored by the test runner.
- Actual endpoint automation tests verify cleanup of ordinary background children before a success receipt, agent death during an approved script, an interrupted receipt after restart and no duplicate script execution. Process tests verify inherited-lock closure, retained capacity while a group remains, and exactly one watcher when a command builder is reused. An isolated seccomp fixture denies the required Linux close-range syscall and verifies installer refusal before state changes. Mac watcher code passes both cross-target checks; native Mac process/runtime validation is still required.
- The scanner/adapter supervisor and endpoint controller passed 32 real-ClamAV lifecycle/setup/health-preparation checks in a disposable Linux container. These cover dedicated identity, broker verdicts, persisted ownership, startup/refusal checks, crashes/recovery, update exclusion and automatic filesystem preparation. Setup tests verify independent signature copies, private scanner ownership, actual scanner/broker startup, rejection of linked or user-writable signatures and foreign ownership, exclusion during active protection, and preservation of disabled local policy. The fixture uses explicit Linux dispatches for Mac setup and supervision; numeric identities are supplied in the container. Five account tests separately cover journaled creation, interrupted setup recovery, foreign/changed/shared records, failed journal persistence and structured attribute decoding. Both Mac native-adapter targets previously passed Clippy; a full endpoint cross-check is blocked by `libproc`'s host-specific generated bindings. Additional checks exercise all health-sample operation baselines, actual custom signatures for text/executable samples, refusal to prepare during a live service, refusal to infer prevention from scanner liveness, and exact sample recognition during approved scans. Native Directory Service operations, installation, lifecycle and blocking remain untested. The Mac supervisor now implements automatic blocking health, but these Linux fixtures deliberately remain unverified.
- Optional Mac native-component packaging passed catalog hash/architecture checks, an actual installer-metadata command test, seven Python packaging tests and five installer-ordering tests. Packaging verifies private snapshots before publication. Hash/signature/entitlement failures leave an existing service untouched. Native setup failure retains the bootstrap and prevents service startup so setup can be retried; it does not roll back a completed engine package install. Apple-tool replies are controlled in these tests; signature acceptance, native installation and authorization on a Mac are not validated. See [the native component packaging contract](macos-native-adapter.md#verified-build-component-in-portal-installers).
- Formatting and Clippy with warnings denied passed, including the Windows cross-target endpoint lint check. `cargo audit --deny warnings` reported no advisories or warnings; the native socket adapters avoid the unmaintained transitive dependency identified during implementation.
- Linux native prevention passed 23 container checks with the actual ClamAV daemon and monitor: clean/blocked reads, new subdirectories, private-file scans, approved quarantine/restore, automatic quarantine, durable case exports, installer readiness, stopped-process detection, crash cleanup, restart and replaced-folder detection. Protected mutations verified pinned reader identities, independent retained bytes, completed filesystem/database records, atomic restore and recovery after discarding a real worker's reply. The controller checks also verified automatic replacement only commits after native blocking is active, a management crash leaves prevention running, and a controller restart restores blocking. The portable real-scanner regression rejects forged reports targeting clean bytes without admitting partial evidence.
- The macOS authorization adapter passed Intel/Apple-silicon cross-target Clippy checks against the actual Endpoint Security bindings. Its Unix scan/response/mutation transport passed 22 container checks against ClamAV 1.5.4, including exact clean/detected hashes, scope rejection, another-UID rejection, observed queue saturation/recovery, broker crash/restart, symlink/FIFO/file-budget rejection and unavailable-scanner failure. The added real-engine checks verify independent quarantine retention, restore conflicts, atomic publication and committed-operation recovery. A real fanotify permission barrier denies ordinary root reads while broker-based quarantine, restore and recovery work; a missing broker cannot fall back to direct reads. The operation helper confirms that an open denial does not imply memory-map blocking. A separate Mac-only validation command requires matching native receipts for open/execute/mmap denials and tests protected-file responses; it has not been executed on a Mac and now requires the supervisor’s automatic blocking proof to become verified. Agent process tests verify broker-based scans, exact-hash quarantine/restore, lost worker acknowledgements, preservation of issued receipts, refusal after broker death and atomic evidence admission on scan failure. Portable response tests exercise the actual executable with no configured broker, including retained-byte independence, out-of-scope/symlink rejection, restore conflicts and adoption of legacy quarantine records. Fifteen mutation tests cover simulated interruption boundaries, changed parents, damaged journals, concurrent replacements, retained-byte independence from old open writers, reader lock lifetime, legacy intent compatibility, local-verifier admission and recovery without a scanner. Separate child-process and hash tests cover intentional descriptor inheritance, unrelated-exec exclusion and exact file identity. No kernel-uninterruptible filesystem or sudden power-loss test was performed. Apple's authorization API was not executed; native prevention and installation on a Mac remain unverified. See [the native adapter contract](macos-native-adapter.md).
- Native receipt delivery passed six transfer tests covering outbox pressure, restart/acknowledgement recovery, changed receipts, invalid scope/verdicts, unsafe files/permissions and batch limits. The actual TCP fixture now runs the endpoint executable against the server. It retained evidence while the server was offline, recovered after restart, completed configured exact-hash quarantine and preserved the original receipt in the case export without setting real-time health. It uses a controlled authorization receipt; execution of Apple's API and responses against actively blocked files remain unverified.
- Linux release-binary journey passed installer download, native process/socket capture, enrollment, server-identity rejection, approved inventory, receipt export, portal-reviewed signed release delivery, local replacement, installed-release health reporting, forced restart recovery, offline error exit and complete backup verification.
- Signed local updates passed 11 real-process checks: tamper/expiry rejection, idempotent staging, running-service exclusion, successful replacement followed by the enrollment/response/recovery journey, failed-readiness rollback, replay rejection, updater-death cleanup, and forced crashes before and after replacement. Fresh temporary signing keys and disposable installation paths were used.
- Automatic maintenance passed five real-process checks: separately approved installation, rollback of a candidate that passes the preliminary readiness command but fails at runtime, recovery after controller death during the trial, preservation of failed release sequences, and exclusion of a second controller. These fixtures use temporary signing keys and disposable processes; they do not install host services.
- Fleet rollout passed six real-process checks with two endpoint controllers: exact reviewed membership, observed canary health before promotion, server restart without duplicate deployments, installation on both devices, the final group's health window, and a bad canary rolling back without dispatch to the remaining device. The scanner-version helper supplies controlled health for this fixture; AV detection is covered separately by the native-prevention checks. No host services are installed.
- Headless Chrome passed installer download, signed-release proposal/review, explicit automatic-installation approval and separate staging/installation receipts, device evidence navigation and response controls, plus endpoint/update/rollout/evidence/storage pages at 1,440px and 390px (ten layouts). Rollout proposal, exact approval, pause, resume, cancellation and export passed. The rollout page and expanded approval content were also visually inspected at both widths. Local captures are in ignored `.athernex/verification/`.
- Windows atomic job creation, bounded pipe output, bounded worker input, cleanup admission and journaled quarantine/restore passed cross-target Clippy with warnings denied. Seven Windows process tests plus their helper, seven Windows filesystem/recovery tests and two actual agent/worker recovery tests linked successfully; they have not been executed on Windows. Two portable command-line encoding tests ran in the Linux workspace suite. The shared mutation refactor also passed both Mac native-library cross-target checks, the full Linux workspace tests and all 22 real-ClamAV Unix response checks. The portal installer/enrollment/response/restart journey passed against the rebuilt Linux release. Windows directory flush, ACL, reparse, atomic publication and recovery behavior still require native execution.
- Updated Linux x86_64 and Windows x86_64 development binaries were built locally. Windows was cross-compiled and its imported DLLs checked; it was not executed on Windows. macOS artifacts and the native CI matrix were not executed in this workspace. No installed endpoint service or global antivirus configuration was changed by verification.

## Continuous collection and controller checkpoint (2026-10-24)

- The workspace passed 267 tests, with one intentionally ignored process-fixture helper. Formatting and strict workspace Clippy passed. The endpoint also passed Windows cross-target Clippy; this did not execute Windows code.
- Independent sampling and AX-006/007/008 have regression coverage for stalled management, durable queue contention, restart, out-of-order evidence, identity boundaries, replay claims and transactional failure.
- Local signed controller updates passed 15 real-process checks on Linux, including supervision after replacement, exclusion of live services, wrong-entrypoint rejection, rollback, interrupted preflight/replacement recovery, blocked startup during an unfinished transaction, and preservation of the agent's bytes and ledger. Eleven signed agent-update regression checks also passed.
- Automatic agent updates passed six checks with active collection: installation, runtime failure rollback, controller-crash recovery, failed-sequence preservation, single-controller ownership and delivery of fresh observations after replacement. Partial host snapshots remain visible; the fixture does not require complete host visibility.
- The Linux development catalog was refreshed. Native Windows/macOS execution and signing, full tamper resistance, native event/authentication coverage, unattended controller/engine maintenance remain open requirements.

## Staged engine checkpoint (2026-10-24)

- The Linux workspace passed 283 tests (two explicit fixture helpers ignored), including nine engine lifecycle unit tests and two signed-tree protocol tests. Four Python bundle tests passed. Strict Linux workspace Clippy and focused engine formatting passed.
- Eight real-ClamAV engine checks passed in a disposable Linux container: live staging/exclusion, activation, selected private-library loading after restart, runtime rollback, prior-engine restart, updater-death recovery, altered-tree rejection and preservation of global engine/agent history. The existing native-service fixture also passed all 32 checks after the service-plan changes.
- Both Mac native-library cross-target lint checks passed. The endpoint/protocol/native crates compile for Windows; strict Windows lint is currently held by unused service methods in the other run's unfinished Windows integration. Whole-workspace formatting also includes that ongoing work. These checks do not establish native Windows/Mac activation or installation.
- The Linux development artifact was refreshed with the verified engine implementation. Local signed engine staging and recovery are implemented; unattended controller/engine delivery, native platform release validation, full tamper resistance and broader event coverage remain open.

## Automatic engine checkpoint (2026-10-24)

- Fourteen engine unit tests and the 82-test endpoint/protocol suite passed. Authorization tests cover local opt-in, exact release identity, expiry, cancellation, update-lock contention, policy revocation, controller ownership and recovery boundaries. Strict Linux workspace and Windows cross-target Clippy passed at this checkpoint; Windows execution remains unverified.
- The controller-owned ClamAV fixture passed 11 checks. It installs without manual stop/restart, restores active protection after a failed trial and recovers a controller-killed trial automatically on restart. All eight manual engine checks, six automatic-agent update checks and 15 local-controller replacement checks also passed.
- The Linux development catalog was refreshed. Explicit local unattended engine activation is implemented and verified on Linux. Fleet engine delivery/receipts, unattended controller replacement, native Windows/Mac release validation, full tamper resistance and wider telemetry remain unfinished.

## Launcher and unattended controller checkpoint (2026-10-24)

- The endpoint/protocol suite passed 87 tests, including five launcher authorization, ownership and executable-integrity tests. The telemetry child fixture remains ignored as a standalone test and is invoked explicitly by its parent integration test. Windows cross-target Clippy passed with warnings denied; this does not execute Windows lifecycle tests.
- The local controller-maintenance fixture passed nine real-process checks: exact requests with cancellation/expiry, launcher exclusion, successful managed runtime confirmation, preservation of agent/configuration/history, failed-candidate rollback, launcher-death recovery, refusal to adopt manual transactions, pre-execution signed-byte verification and recovery of a missing agent destination.
- The Linux native-prevention fixture passed 26 checks with real ClamAV. The three new launcher checks verify controller replacement only confirms with actual blocking, launcher death cleans management/controller/root-monitor/dedicated-UID scanner processes, and restart restores verified prevention. The process-exit observer was corrected to accept a process disappearing during its `/proc` read; production lifecycle code was not changed to mask this fixture failure.
- Regression fixtures passed 15 manual-controller, six automatic-agent and 11 automatic-engine checks. The Linux development package was refreshed. CI runs the local controller fixture on Linux/Windows and the real prevention fixture on Linux.
- Exact local unattended controller maintenance is implemented and verified on Linux. The stable launcher remains installer-maintained. Fleet controller/engine delivery, native Windows/Mac execution and release signing, hostile-administrator tamper resistance, broader native telemetry and sustained fleet reliability remain open requirements. Detailed results and source/log hashes are in `.athernex/verification/automatic-controller-validation.json`.

## Reviewed controller delivery and collection checkpoint (2026-10-24)

- The Linux workspace passed 323 tests, including the 91-test endpoint/protocol suite and ten signed-update transport/policy tests. Two standalone fixtures remain ignored: the telemetry child is invoked by its integration test; the Windows-filter stream test requires its separate real-ClamAV fixture, which was not rerun at this checkpoint. Strict Linux workspace and Windows cross-target Clippy passed. Windows execution remains unverified.
- The reviewed controller-delivery fixture passed eight real-process checks against the final development artifact: separate local permission, staging without replacement, cancellation, exact component review, runtime installation with two receipts, failed-candidate rollback, recovery while the server is unavailable, and immutable receipt delivery after server/launcher restart. Agent bytes, configuration and release history remain unchanged during controller replacement.
- Regression fixtures passed nine local-controller maintenance checks, six automatic-agent checks, six agent-rollout checks and 26 real-ClamAV prevention checks. Native blocking remains covered by the separate container fixture; the fleet transport fixture uses no antivirus backend. The final agent regression also verified fresh continuous observations after replacement.
- A busy-host test exposed an unnecessary sampling pause while 1,159 existing observations awaited forwarding. Sampling now continues while the bounded durable queue has room. A full queue pauses capture, and samples that do not fit cannot advance the comparison cursor. The stalled-network test captured its new process in about two seconds through the durable queues without relaxing its ten-second deadline. A separate unit test verifies full outbound-queue behavior, preservation of earlier observations and the 8,192-record pending limit.
- Headless Chrome passed controller proposal/approval and receipt controls, existing installer/agent/rollout controls, and ten layouts at 1,440px and 390px. Controller policy and exact component review are displayed separately; the installation checkbox uses the existing inline label style. Captures are retained in `.athernex/verification/`.
- The Linux development catalog was refreshed from the exact endpoint bytes exercised by the final controller-delivery fixture. Fleet engine delivery and controller rollout groups, native Windows/macOS validation and signing, stronger tamper resistance, wider native event coverage and sustained fleet reliability remain unfinished. Detailed evidence is in `.athernex/verification/fleet-controller-delivery-validation.json`.

## Controller fleet rollout checkpoint (2026-10-24)

- The portal and scheduler now support reviewed controller groups with independent controller policy, sequence history and launcher health. Approval binds the selected component and each device's reported agent version/installed-release identity. Those agent values must survive approval, dispatch and observation. Existing agent-plan serialization and hashes remain compatible.
- Eleven rollout tests passed, covering restart/promotion, exact approval, component policy, changed agent identity, wrong-component health, missing launcher supervision, stale observations and existing failure/cancellation behavior. Strict workspace Clippy passed. The full Linux workspace rerun passed 340 tests with two fixture helpers ignored; the first run ended with signal exit 143 during a storage test without reporting an assertion failure. The complete retry passed that test as well.
- Disposable two-device runtime fixtures passed seven controller checks and six agent regression checks. Both exercised distinct signed executable bytes, real installation, server restart, observed 60-second health windows, and failed-canary rollback with no later dispatch. Controller replacement and rollback preserved agent bytes, configuration and agent release history. The fixtures use controlled scanner-version health, not antivirus detection; prior native-prevention evidence is separate.
- Headless Chrome passed agent/controller proposal, review, pause/resume/cancellation and export, plus ten layouts at 1,440px and 390px. The controller review was visually inspected at both widths. CI now runs both component modes on its non-Mac endpoint jobs.
- Runtime validation used the new unoptimized SIEM server build in temporary storage and the previously verified Linux endpoint release artifact. This server-only change did not refresh the endpoint package or modify installed services. Native Windows/macOS validation and signing, fleet-engine delivery validation, stronger tamper controls, broader native event coverage and sustained fleet reliability remain unfinished. Evidence is retained in `.athernex/verification/controller-rollout-validation.json`; the complete original scope is tracked in `.athernex/verification/remaining-endpoint-requirements.json`.

## Fleet engine recovery checkpoint (2026-10-24)

- Fleet engine activation now binds its exact deployment into the durable controller request. Terminal receipts survive server loss and repeated controller recovery, and later maintenance cannot overwrite an unacknowledged result. New fleet work cannot adopt an unrelated local request for the same release. Stored results remain deliverable after managed updates are disabled.
- A repeated staging refusal is now recognized as the original staging receipt, rather than an unauthorized installation result. Changed replay content remains rejected. The portal exposes exact device plans/hashes and permits cancellation after approval until installation is authorized. Rollout members use their group controls, matching the server's immutable group authorization.
- Eighteen engine unit tests passed, including deployment binding, policy revocation, local/fleet ownership, corrupt-journal rejection, expired offline recovery and receipt retention. The final Linux workspace passed 346 tests with two standalone fixture helpers ignored. Strict Linux workspace and Windows cross-target lint passed. The Windows check initially encountered concurrent scratch-storage imports before those were corrected; native Windows execution remains unverified.
- The optimized Linux fleet fixture passed 16 real-ClamAV checks: signed transport, staging-only behavior, exact reviewed installation, native blocking and private-library selection, rollback, controller loss, recovery while the server is offline, immutable receipt delivery after restart, refusal to adopt a local result, and tampered-tree retention. Eleven local automatic-engine regression checks also passed. The initial debug fixture exposed a stale-health wait; a later unoptimized run exceeded its 90-second fault-injection wait. The final optimized run retained that deadline and passed. The verifier snapshots its inputs, reports their hashes, and cleans only its own container on termination.
- Browser checks passed for populated device review, cancellation after approval, both receipt types, exact canary membership, pause/resume/cancel, and two visually inspected layouts at 1,440px and 390px. Those browser receipts are controlled fixtures; native installation is covered separately.
- The development Linux catalog now contains the exact optimized endpoint exercised by the final fleet fixture. Detailed evidence is in `.athernex/verification/fleet-engine-delivery-validation.json`. Portable group tests and browser review passed; real multi-device engine promotion, native Windows/macOS release validation/signing, stronger tamper controls and broader XDR coverage remain open.

## Native engine rollout checkpoint (2026-10-24)

- Two independent endpoint states and controllers passed ten real-ClamAV group checks in one isolated Linux container: exact reviewed installation, 60-second health windows, preserved observation state across server restart, private-library selection, blocking, failed-canary rollback and no delivery to the later device. Completed and failed groups remained terminal across restart without duplicate deployments. This is native process evidence on one kernel, not a separate-host load or detection-coverage evaluation.
- The native run exposed a telemetry health race: an ordinary in-progress capture briefly reported incomplete collection and stopped a healthy canary. Health now retains the last completed result while the same live capture is within its deadline. Its success timestamp is not advanced. Failed, stalled, interrupted and reopened captures remain unhealthy. Snapshot health and the initial pending-to-outbound transfer commit atomically; failed admission preserves earlier cursors and observations.
- Eleven telemetry tests, including three new concurrency/recovery/admission cases, passed within the final 352-test workspace run; two standalone helpers remain ignored. Strict Linux workspace and Windows cross-target Clippy passed. The Windows check encountered concurrent scratch-storage lint changes; native Windows execution remains unverified.
- All 16 single-device native engine recovery checks also passed with the new optimized endpoint. CI now runs the group fixture. The verifier pins readiness to the exact child incarnation, snapshots its inputs and retains diagnostics for failures. No production health or observation gates were relaxed.
- The Linux development package was refreshed from the tested endpoint (`93970cd4872f8fecbf2c3afcdf4749d800e989cb5ff5717c9ce099aec62fdc8d`). Evidence is in `.athernex/verification/engine-rollout-validation.json`. Native Windows/macOS installation/recovery and signing, stronger tamper controls, broader native event coverage and sustained fleet reliability remain open.

## Native Linux process-event checkpoint (2026-10-24)

- Added opt-in Linux kernel lifecycle collection independently of snapshot sampling and management requests. Typed originals retain kernel process/thread IDs, sequence and time without inventing executable identity. Subscription boundaries, loss, queue overflow and worker freshness are visible in device health and evidence exports. An approved rollout cannot silently lose its native-event requirement; legacy plan serialization remains unchanged when the feature is absent.
- The workspace passed 359 tests with five explicit fixtures ignored. All three native process-event fixtures passed separately in a bounded container and under the local user: 24 immediately exiting children during stalled HTTP, exact durable records through restart/authenticated export/replay, portal coverage visibility, actual agent termination/restart and continued collection, and a forced receive-socket overflow. The other standalone helpers retain their existing invocation requirements. Strict Linux workspace and Windows cross-target Clippy passed; the latter does not execute Windows code.
- The optimized endpoint passed the native event fixtures. The same endpoint/server pair passed all ten real-ClamAV engine rollout regression checks, including both observation windows, server restart, failed-canary rollback and containment. The Linux development catalog now contains endpoint SHA-256 `1aa0c6fb0ab5d5847cbf6a488ef1339ee73484bb80814d1280bc859190572851`; it remains unsigned for production.
- Source/log hashes and checks are recorded in `.athernex/verification/process-events-validation.json`. Native Windows/macOS execution/signing, platform tamper controls, authentication and broader network events, measured detection quality and sustained fleet reliability remain open. This checkpoint does not claim lossless collection or completion of the original endpoint requirements.


## Native Linux authentication checkpoint (2026-10-24)

- Added opt-in journal authentication collection with exact original SSH/PAM reports, durable cursor admission, explicit retention/sequence/queue gaps and a bounded journal-writer health check. Claimed accounts remain device-scoped and separate from reporter UIDs. Repeated denials feed the existing authentication investigation rule; the portal and authenticated exports preserve originals.
- The full workspace passed 369 tests with seven explicit helpers/fixtures ignored. Two additional rollout tests then passed within a 17-test rollout regression run, proving that agent, controller and engine plans retain their reviewed authentication requirement and stop promotion when that coverage disappears or reports loss. Strict Linux workspace and Windows cross-target lint passed; cross-compilation does not execute Windows code.
- Both private native SSH/journal fixtures passed with the optimized agent available to the actual-agent fixture. They covered real allow/deny reports, stalled HTTP, exact replay after collector restart and actual agent termination, a login written while the agent was dead, journal retention loss, an unresponsive writer, authentication-burst detection, original-evidence navigation and authenticated exports. The unit integration harness uses its compiled SIEM library; the actual-agent fixture runs the optimized executable. PAM message parsing has portable tests, but native PAM-provider validation remains open.
- All three existing native process-event fixtures passed with the new optimized agent. The same endpoint/server pair passed ten real-ClamAV engine rollout regression checks, including both observed health windows, server restart, failed-canary rollback and containment. These fixtures use one Linux host and do not establish sustained separate-host fleet reliability.
- The Linux development catalog was refreshed from endpoint SHA-256 `1d6eb0d52b1a0f8b861eb4ec563e7fcb3c16f2f3208fb8f646ba6e6daa06efd4` and remains unsigned for production. Source/log hashes and limitations are recorded in `.athernex/verification/authentication-validation.json`. Native Windows/macOS execution and signing, platform tamper controls, broader authentication/network coverage and measured detection/load behavior remain open in `.athernex/verification/remaining-endpoint-requirements.json`.


## Native PAM and authentication accuracy checkpoint (2026-10-24)

- A new native PAM fixture reproduced a false AX-001 alert: eight successful SSH logins each reported a failing `pam_unix` module before a later PAM module accepted the login. Endpoint and local-journal normalization now retain module failures as observations. Only the service report supplies an allow/deny outcome; duplicate PAM and SSH reports cannot accelerate the denial threshold. The portal distinguishes module reports, and original payloads/IDs remain unchanged.
- The native fixture also filled the 8,192-entry pending queue and 3,072-entry outbound budget, recorded an actual PAM/SSH denial, restarted collection while full, then released a small amount of capacity. The exact cursor and older queued observations survived; both waiting reports were admitted once and remained exact after another restart. No source journal, account or PAM policy on the host was modified. The PAM test policy is confined to a private tmpfs and network namespace; the verifier checks those boundaries before writing it.
- All three native authentication fixtures passed after the correction. Portable endpoint and host-journal tests verify the denial threshold, exact original replay and the portal's module label. The workspace passed 373 tests with eight explicit helpers/fixtures ignored; the three authentication fixtures were run separately. Strict Linux workspace and Windows cross-target lint passed. The Windows check remains compilation evidence only.
- The development catalog now contains tested endpoint SHA-256 `1bbbcc555ba6e884e48d19bca3d69ae7df22c9ddcf3a741eecee9bd3e587a918`. The optimized server was rebuilt as well. The report `.athernex/verification/pam-authentication-validation.json` records the failing reproduction, final checks, exact binary/log hashes and limits. Native PAM evidence covers `pam_unix` with controlled denying/fallback stacks on this Ubuntu fixture; it does not establish all providers/distributions, a production false-positive rate, sustained fleet load or completion of the original platform/tamper requirements. Previously stored normalized records and investigations are not rewritten by this correction.


## Native network tracker checkpoint (2026-10-24)

- Completed the interrupted optional Linux network-event collector, typed protocol,
  durable queues, agent lifecycle, server normalization, portal evidence and rollout
  health gates. Network events remain disabled by default.
- Three explicit native network fixtures passed in separate private network
  namespaces. They prove startup refusal without tracking, detection of removed
  hooks, real receive-socket overflow, 16 short-lived IPv4/IPv6 TCP/UDP flows during
  stalled actual-agent HTTP, explicit tracker removal with counters, crash/restart
  gaps, resumed collection, exact authenticated export and replay after server reopen.
- Native testing exposed a real hook-header difference: data headers can use port
  zero while completion echoes the bound socket port. The correction preserves
  kernel-sender, request-sequence and complete-dump checks. The failed reproduction
  and passing rerun are retained with the verification logs.
- The workspace passed 379 tests with 11 explicit fixtures ignored. After the
  localized native header correction, all five focused network tests, all nine
  explicit native network/process/authentication fixtures, and strict Linux and
  Windows cross-target lint passed. The separate optimized agent/server pair
  passed ten real-ClamAV engine-rollout regression checks, including observed
  promotion, server restart, rollback and containment. Cross-target lint does not
  execute Windows code.
- Refreshed the development-unsigned Linux catalog with the exact tested endpoint:
  SHA-256 `7e76989c800683f618e2126c70d3dcca49940eaccd2fa1d2c95fe40b4d922d67`.
  Evidence and input/log hashes are recorded in
  `.athernex/verification/network-events-validation.json`.
- This checkpoint covers tracker observations in checked namespaces/families.
  Process attribution, traffic bypassing tracking, additional providers/platforms,
  sustained fleet load, native Windows/macOS release validation/signing and platform
  tamper controls remain open in the original requirements audit.

## Measured native network load

The shared detector indexes eligible facts in its temporary RAM cache before
expanding labels and JSON context. The index is reconstructed from encoded facts
on restart, including legacy ledger imports; the persisted schema is unchanged.
Passive `observe` records remain in the original evidence and hot window, while
rules that consume only `allow`/`deny` facts avoid traversing them. This avoids repeating that work for the entire recent
history on each tracker observation. A differential regression compares all five
generic rule results and their exact evidence against the full-history path,
including passive records, late arrivals and expired authentication windows.
Cache eviction selects only excess rows while preserving the same ID, time and
size limits. A restart regression verifies that previously disabled authentication
detections can still use restored facts when re-enabled.

The opt-in network fixture also measures sustained delivery through the actual
agent and an HTTP server using the SIEM engine. It generates paced TCP/UDP flows
over IPv4 and IPv6, returns HTTP 503 for a 30-second outage, kills and restarts the
agent, and continues traffic while the backlog drains. Run it in the existing
private network fixture:

```sh
cargo test --locked --release -p athernex-endpoint --lib --no-run --message-format=json > /tmp/network-tests.jsonl
python tools/verify_network_events.py --manifest /tmp/network-tests.jsonl \
  --agent target/release/athernex-endpoint --soak-seconds 120 --soak-rate 8 \
  --report /tmp/network-load.json
```

Measured runs require an optimized test server; the runner refuses an unoptimized
test manifest. Supply the optimized agent build as shown above.
The runner prints fixed outcomes and keeps captured native output in a private
`athernex-network-diagnostics-*` directory under the system temporary directory.
Those diagnostic files are excluded from the uploaded measurement artifact.
Each online/recovery phase accepts 60–600 seconds at a target of 1–16 flows per
second. The report pins the executable and container image hashes and records
actual phase durations, queue high-water samples, agent peak resident memory,
flow completion latency, exact original/replay checks and collector loss counts.
The shown workload contains 2,160 tracked flows plus eight deliberately
unobserved flows while the agent is dead. Every tracked flow must have both
creation and removal evidence at the server. A crash must leave an explicit
coverage gap; unexpected queue/kernel loss fails the check.

The fixture checks that its benign tracker observations do not create network
investigations or turn cumulative counters into byte deltas. This measures one
synthetic workload on one Linux kernel, not a production false-positive rate,
multi-host capacity or lossless arbitrary-load coverage. Optional intermediate
kernel updates have no independent expected count. Delivery latency includes
the fixture's observation interval. Protection, signing, native Windows/macOS
validation and the other original requirements remain separate gates.

The optimized Linux run on 2026-10-24 delivered all 2,160 flows and 10,800 tracker
records, preserved 10,685 sampled local originals and replayed all 10,800 records
without duplicates. All 1,200 records captured during the server outage survived.
No queue drops or unexpected kernel loss were reported; the deliberate agent
crash remained a visible coverage gap. The backlog drained 54.9 seconds after
traffic generation stopped. Recovery-phase p95 completion latency was 56.2
seconds, so this is bounded recovery evidence, not a steady-state capacity or
latency guarantee. Phase labels identify when traffic was generated; late online
records can include outage delay.

The pre-change optimized run left 532 flows incomplete at the unchanged
90-second drain deadline; an intermediate context-only optimization left 260.
The final indexed detector and eviction changes passed the same workload and
deadline, 396 workspace tests, strict workspace lint and six additional native
network/SSH/PAM checks. CI uses the measured 120-second online/recovery phases.
Input, source and log hashes, failed runs, final metrics and remaining limits are
recorded in `.athernex/verification/network-soak-validation.json`. The Linux agent
package is unchanged; an updated SIEM executable and the optimized test fixture
are retained in `.athernex/verification/network-soak-build/`.

### Isolated endpoints with the actual server executable

`tools/verify_network_fleet.py` runs two real endpoint processes in separate
Docker PID/network namespaces against one actual SIEM executable. Both private
namespaces contain only loopback; Unix-socket relays carry management HTTP to the
fixture server on host loopback. Tracking rules, tracker deletion and the
accounting sysctl are confined to those namespaces. The fixture does not change
host networking or install a host service. It needs the same network test image
as the single-endpoint check and optimized Linux x86_64 executables:

```sh
cargo build --locked --release -p athernex-endpoint -p athernex-siem
python tools/verify_network_fleet.py --agent target/release/athernex-endpoint \
  --server target/release/athernex-siem --seconds 180 --rate 4 \
  --report /tmp/network-fleet.json
```

Each endpoint generates paced IPv4/IPv6 TCP/UDP traffic during an online phase,
a 30-second server outage, and a recovery phase. The server is killed rather
than returning a simulated error. During the outage only the first agent is
killed and restarted; eight flows generated while it is dead must remain absent,
and its coverage must retain the interrupted subscription. The second collector
must retain its original subscription without acquiring its peer's gap.

Every expected flow needs both created and removed observations. The check also
compares sampled local originals with server evidence, verifies namespace
separation, restarts the server again and independently rereads its committed
observations, and submits exact authenticated replays that must create zero new
records. Unexpected loss, queue drops or network investigations fail the run.
Reports include binary/image hashes, actual phase durations, per-endpoint queue
and RSS samples, and observed completion latency. Failed runs retain a report
and a private temporary directory with worker/server logs. Cleanup removes only
containers named by the fixture's recorded IDs and terminates owned processes.

This supplies evidence for concurrent instances on one kernel. It does not
establish reliability across separate hosts, WAN/TLS behavior, production
detection quality, or indefinite throughput. Intermediate tracker updates have
no independent expected count; created/removed boundaries do. The CI workflow
configures the 180-second phases at four flows per second per endpoint, but a
local run does not establish that CI executed it.

The local run on 2026-10-24 passed with 3,128 flows and 15,640 tracker records
across the two endpoints. All 14,575 sampled local originals matched the server,
and authenticated replay of all 15,640 records created no duplicates after the
second hard server restart. No queue drops or unexpected loss were reported.
The deliberately restarted agent retained one gap and two subscriptions; its
peer retained one uninterrupted subscription. The eight flows generated while
the first collector was dead remained absent. The backlog drained 3.5 seconds
after traffic generation stopped. Recovery-phase p95 completion latency was
19.6 and 25.0 seconds; these are observed workload results, not a latency SLA.
The server outage lasted 34.0 seconds including coordination and agent restart.
Late online records can include outage delay in their completion latency.

The initial run reached its final alert check, then failed because the verifier
looked for findings in the summary API response. The verifier now reads the
evidence-export API, and the complete workload was rerun successfully. Both
reports, binary/source hashes, logs, isolation checks and remaining limits are
recorded in `.athernex/verification/network-fleet-validation.json`. The matching
executables are retained in an isolated verification directory; no portal
catalog promotion or production release occurred.

## Native sudo authentication checkpoint (2026-10-24)

The sudo parser and local journal normalization changes passed 416 workspace
tests, with 14 explicit native fixtures ignored by that portable run, plus
strict Linux workspace and Windows endpoint cross-target lint. Six new portable
tests cover report grammar, command-text injection, account/outcome consistency,
local classification and missing-provenance coverage. No Windows runtime was
executed by these checks.

Five native authentication checks passed with the matching optimized agent:
the existing SSH delivery/restart and PAM queue/fallback checks, the new sudo
scenario, and a separate missing-provenance scenario. Real sudo/PAM produced
25 retained authentication records: 17 module observations and eight completed
service denials. Exact originals and replay survived collector/server reopen.
Eight successful PAM fallbacks produced no denial burst, an aggregate two-try
failure counted as one service report, and the detector fired at eight service
reports. Native `NOPASSWD`, policy refusal and command-argument controls did not
become false authentication outcomes. The local collector also classified the
actual sudo command and policy-control records correctly.

The fixture's read-only image contains sudo 1.9.15p5, PAM 1.5.3 and systemd 255.4
on Ubuntu 24.04. Its private PAM/sudoers tmpfs mounts and root identity helper
are test setup, not host provisioning. The helper supplies sudo's normal entry
identity (real UID 60000, effective UID 0) while Docker's no-new-privileges setting
remains enabled. The positive fixture grants journald executable-inspection
permission only inside its private PID namespace. The separate negative case
omits that permission and verifies real records without `_EXE`: no authentication
facts are invented, and rejected-record/degraded coverage persists after restart.

Run both gates after building the existing auth-test image and a matching native
test manifest:

```sh
python tools/verify_auth_events.py --manifest /tmp/auth-tests.jsonl \
  --agent target/release/athernex-endpoint
python tools/verify_auth_events.py --manifest /tmp/auth-tests.jsonl \
  --agent target/release/athernex-endpoint --missing-provenance
```

The CI workflow configures both invocations; it was not dispatched from this
checkpoint. Evidence, source hashes, exact artifacts and the initial fixture
corrections are recorded in `.athernex/verification/sudo-authentication-validation.json`.
Other distributions, localized/custom sudo formats, additional providers and
native Windows/macOS collection still need validation. The original prevention,
tamper-resistance, signing and fleet requirements remain open.
### TLS certificate faults in the native fleet workload

`tools/verify_network_fleet.py --tls` extends the two-endpoint Linux workload
with actual agent TLS verification. A private fixture proxy terminates TLS and
forwards to the real SIEM executable on loopback. The isolated namespaces carry
encrypted connections through Unix relays. The fixture configures its temporary
CA through each agent's `ca_file` before enrollment; it never disables certificate
verification or changes the host trust store.

After the online workload, the proxy presents an untrusted issuer for 30 seconds,
then a certificate signed by the trusted CA with the wrong server name for
another 30 seconds. Each phase requires rejected handshakes, no decrypted client
request reaching the SIEM, and retained original flow boundaries in both agents.
The collectors must remain active without new loss or drop signals. The proxy
then rotates to a new valid certificate under the original CA. The workload
continues through a hard server outage, one agent crash, recovery, a second
server restart and authenticated duplicate replay over TLS. Completion still
requires every expected flow boundary and exact sampled local original.

Run against the already built network fixture image:

```sh
python3 tools/verify_network_fleet.py \
  --agent target/release/athernex-endpoint \
  --server target/release/athernex-siem \
  --seconds 300 --rate 4 --tls \
  --report /private/output/network-tls-fleet.json
```

The report includes certificate fingerprints, negotiated TLS versions, handshake
failure counts, queue measurements and exact recovery/replay checks. The helper
uses Python's [TLS socket API](https://docs.python.org/3/library/ssl.html), draining
buffered decrypted bytes before waiting for another TCP readability notification.
Only the owning connection handler closes its TLS object during certificate
changes. Temporary keys and credentials stay in the private retained fixture;
they are excluded from the report.

This covers a local TLS termination model and bounded certificate faults. It
does not establish WAN behavior, packet-loss behavior, separate-host capacity,
the production reverse proxy's configuration, or native Windows/macOS coverage.
The workflow retains the TLS report on both success and failure.

The local TLS checkpoint passed with 300 seconds each of online and recovery
traffic at four flows per second per endpoint. Across both agents it recorded
5,528 expected flows and 27,640 tracker records; 26,380 sampled local originals
matched exactly after delivery, two hard server restarts and authenticated replay.
There were no reported queue drops or unexpected loss signals. The deliberate
agent crash retained one explicit coverage gap, while its peer kept its original
subscription. No synthetic flow from the crash gap was invented.

The proxy observed 12 unknown-CA and 14 wrong-name handshake failures, with zero
upstream connections or decrypted client request bytes under either rejected
certificate. Successful connections negotiated TLS 1.3. An independent OpenSSL
check confirmed the intended issuer/IP-name failures, and both live agent
configurations retained HTTPS and the exact original CA after rotation. Proxy
connection counts include the coordinator's authenticated replay requests.

The measured backlog drained 1.896 seconds after generation stopped. Recovery
completion latency had observed p95 upper bounds of 62.925 and 64.334 seconds;
this includes catch-up from the earlier certificate faults and server outage.
Outbox high-water marks were 2,272 and 2,306 events. These measurements describe
this finite local workload, not a fleet latency or capacity guarantee.

The native report is
`.athernex/verification/network-tls-fleet-validation.json`; source/artifact hashes,
independent certificate/trust checks and retained log hashes are in
`.athernex/verification/network-tls-fleet-checkpoint.json`. Both owned containers
were confirmed removed after the run. Windows/macOS native execution, production
signing, remaining prevention/tamper controls and separate-host validation remain
open.

### Assertions are required for validation

The assertion-based Python verifiers reject `-O`, `-OO` and an enabled
`PYTHONOPTIMIZE` before importing platform helpers or creating fixtures. Their
generated authentication, network, process and peer-verification scripts perform
the same check in the child interpreter. This prevents disabled Python checks
from producing a passing validation report or bypassing fixture isolation checks.

`python3 tools/test_verification_guards.py -v` checks all sixteen verifier entry
points and six generated helpers. The six local regression tests passed,
including refusal of missing native test names and host network namespaces.
The test is part of `make check-endpoint` and the platform CI matrix. This is
validation-runner evidence; it does not execute the Windows/macOS native gates.
The checkpoint is
`.athernex/verification/verification-guards-validation.json`.
