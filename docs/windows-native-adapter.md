# Windows native prevention development

The Windows minifilter and Rust scanner client are a development component. They
compile against the real Microsoft WDK/SDK and Windows APIs. **The driver has not
been loaded or tested on Windows, is unsigned, and is not installed by the
portal. Windows protection policy still refuses activation.** This work does not
establish that Athernex can replace an existing Windows antivirus product.

The endpoint already has Windows installer generation, scanning, automations,
and journaled quarantine/restore. Their status and platform validation limits
are documented in [endpoint-fleet.md](endpoint-fleet.md). This component supplies
the kernel-to-scanner boundary and a development supervisor with durable
detection delivery. Production lifecycle integration, scanner isolation and
observed blocking health remain work to do.

## Implemented boundary

`infrastructure/endpoint/windows-filter/` contains an x64 minifilter for local
NTFS volumes on Windows 10 version 2004 or later. It registers post-create file
checks and a Filter Manager communication port. The matching client is
`core-engines/endpoint-native/src/windows_filter/`.

- A single LocalSystem process connects. The driver retains the exact process
  object, checks it for control requests, and exempts only that connected
  process from recursive file scanning. Reconnection waits for the old
  connection and outstanding scans to finish.
- A policy contains 1–16 normalized NT directory names and a 100–5000 ms
  deadline. The Rust builder binds the roots, ordering and timeout to a SHA-256
  policy identity. The driver validates message sizes, flags, root components
  and zeroed unused fields independently.
- Arming verifies attached volumes and opens directory ancestors without delete
  sharing. Reparse points and pending deletions are refused. These handles stay
  open after scanner disconnect. Scan admission and policy changes share the
  same lock; an admitted scan prevents disarming or replacing its policy.
- In-scope read/execute file opens request a verdict. At most 64 scans remain
  outstanding; the maximum file size is 128 MiB. Each request includes its
  policy identity, volume serial, full 128-bit file ID, path, length and actor
  PID/creation time. Creation times are Windows FILETIME ticks, not Unix time.
- The connected scanner requests a read-only section for that exact pending
  request. The driver verifies metadata, concurrent writers and section
  conflicts. The client reads the mapped bytes through `ReadProcessMemory`,
  streams all bytes to ClamAV, and computes SHA-256 over those same bytes.
- Four client workers connect only to loopback. The actual established TCP
  server tuple must belong to the specified live PID and process creation time.
  This binds transport to a process; the future supervisor must also establish
  trusted executable/configuration provenance and own the daemon's lifetime.
- Only an exact successful, matching, clean reply permits an open. Timeout,
  scanner loss, malformed replies, changed metadata, unsupported sources or
  capacity exhaustion deny it. A section is released before cancelling an open.
  Policy remains armed when the scanner exits.
- A kernel notification records the applied decision. A submitted user-mode
  reply alone is not treated as evidence. Kernel delivery has a 10 ms budget;
  kernel drops, client queue drops and reply failures are counted separately.

The kernel uses an absolute deadline and requires exact `STATUS_SUCCESS` because
`STATUS_TIMEOUT` is a success-class NTSTATUS. See Microsoft's
[FltSendMessage contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage).
Read-only section ownership and cleanup follow
[FltCreateSectionForDataScan](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatesectionfordatascan)
and [FltCloseSectionForDataScan](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltclosesectionfordatascan).

## Current coverage limits

This is a **file-open decision implementation**, not complete execution or
memory-mapping protection. Existing handles, existing mappings, changes after a
clean decision, hard-link aliases outside the configured roots, and complete
read/execute/mapped-image coverage still need design and native validation.
Section-synchronization callbacks currently invalidate concurrent verdicts;
they do not claim to block executable mappings.

Directory pins protect namespace ancestry; they do not make a file immutable.
Transactional opens and unsupported filesystem/source states are refused.
Scanner/state/database locations must be kept outside watched roots by the
eventual service policy. The ClamAV daemon is a separate process and is not
exempted by the current client-process exemption.

Kernel I/O, section creation, view faults and cancellation may outlive an
application timeout. The embedding process needs independent Windows job
ownership, cleanup accounting and a restart policy. Cancellation alone does not
release capacity or make outstanding I/O buffers safe to free. Those lifetime
rules are implemented for the client's overlapped buffers and development
supervisor. Normal installer/controller activation remains disabled.

The development worker drains its bounded observation channel into a SQLite
spool with full synchronization and a 2,048-decision limit. A fresh random session
identity binds each kernel request ID to a unique event ID across driver/client
restarts. A transfer journal preserves replay checks across agent/server ACKs;
changed replays are refused. Queue loss counts persist across restart. Kernel
delivery drops remain a separate driver counter. Neither an armed status nor
counters alone prove active protection. Live clean and
signature-matched probes, including read/execute/mapping cases, are required.

LocalSystem administrators can connect, disarm and replace components. No
protected-service, ELAM, or hostile-administrator tamper resistance is claimed.

## Development service integration

The agent includes `protect-windows-preview PRIVATE_PLAN.json`, an explicit
development entry point. It requires LocalSystem, an existing enrolled endpoint
state, a separately deployed driver and a locally pinned ClamAV executable.
Normal protection configuration continues to reject Windows activation. The
command does not install a driver or modify boot/signing policy.

The plan contains `schema: 1`, `roots` (local drive directories), `state` (the
existing endpoint state directory), `daemon`, `daemon_sha256`, `database`,
`port`, `timeout_ms` (100–5000), `startup_secs` (5–120), and
`scanner_isolation: "restricted-local-service"`. Optional `scratch_mib` defaults
to 2048 and accepts 256–4096 MiB. Plan, agent, scanner, signatures and
state locations must pass the private Windows owner/ACL and no-reparse checks.
Older Program Files installations with readable ACLs may need a separate
private development copy or reviewed permissions migration. The current Windows
installer creates private executable directories. Existing ACLs are not relaxed; new scanner workspace
objects receive explicit, logon-scoped permissions. The earlier
`development-system` mode is rejected.

The scanner token comes from a password-free LocalService service logon with an
explicitly allocated logon SID (`AllocateLocallyUniqueId` and `LogonUserExExW`).
Built-in service accounts can share logon contexts, so exclusivity is not
assumed from the account name. Startup verifies that the returned token contains
exactly the allocated logon SID. The LocalSystem caller must have the enabled
TCB privilege required by this API; failures stop startup. Then
`CreateRestrictedToken` removes privileges other than change notification and
disables groups other than Everyone, BuiltinUsers, the logon SID and the integrity
group. Restricting SIDs are Everyone, BuiltinUsers and that logon SID; the token
is lowered to low integrity. The original token must already have enabled
BuiltinUsers membership. This permits standard-user-readable system DLLs and
other public objects; it does not grant access to private endpoint state or
enable AuthenticatedUsers-only access. Medium-integrity writes remain forbidden,
including to files whose DACL grants BuiltinUsers write access. Public objects
with low integrity can still be writable. Both the token supplied to process creation and the launched process
token are checked. The process/thread owner is explicitly SYSTEM, and their
DACL grants access to SYSTEM and the scanner logon. Each scanner receives a new
noninteractive window station and desktop. An owned SYSTEM worker creates them
with SYSTEM ownership, a low-integrity label and access only for SYSTEM and the
exclusive scanner logon. The scanner cannot change their owner or ACL, delete
them or create additional desktops. The supervisor never
switches its process station. It duplicates the worker's exact object handles,
checks their names/types, and requires the worker and its job to exit before
creating the suspended scanner. The scanner's owned process tree retains these
handles through cleanup, including asynchronous reaping. There is no fallback
to a shared desktop or privileged scanner. This desktop path still requires
native validation; compilation does not establish confinement.

The token's default object owner is also its exclusive logon SID, with the
group marked owner-eligible. A private default DACL alone would leave the shared
LocalService user with implicit owner rights on scratch files. Startup and live
token checks verify the default owner. This uses the documented
[token owner contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner).

These choices follow Microsoft's [LocalService logon example](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera),
[explicit logon groups contract](https://learn.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw),
[restricted token contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken),
[integrity control rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control),
and [process creation desktop rules](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
Their runtime behavior still needs native validation.

A [read-only native probe](https://github.com/CharlesDerek/lab/actions/runs/40204329951)
confirmed that the earlier Everyone/logon-only token could not read five loaded
Windows runtime DLLs. Retaining BuiltinUsers in both access checks allowed those
reads while private-state access was denied. The regular native access test now
requires runtime reads, rejects AuthenticatedUsers-only access, and checks that
BuiltinUsers-writable medium-integrity files cannot be changed, deleted or have
their ACL modified. Process startup and network enforcement must also pass their
separate native tests before scanner isolation can be considered verified.

The subsequent [native station diagnostic](https://github.com/CharlesDerek/lab/actions/runs/40206509968)
found that SYSTEM could open the default LocalService station while the exact
restricted scanner token received access denied. Both process fixtures exited
with `0xc0000142` before helper startup. The private desktop path addresses that
access mismatch; its process launch, cross-logon denial, cleanup and WFP checks
must pass before claiming the startup failure is resolved. Creation uses
Microsoft's [exclusive window-station creation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowstationw)
and [desktop association rules](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createdesktopw).

A [loader trace and per-right comparison](https://github.com/CharlesDerek/lab/actions/runs/40209408033)
then identified `USER32.dll` process-attach failure. On the hosted Windows Server
2022 VM, adding only `WINSTA_EXITWINDOWS` to the private station let the helper
reach `main`; adding only `WINSTA_CREATEDESKTOP` or granting full desktop rights
did not. The station now includes the observed required right, while retaining
the desktop-creation and owner/ACL/deletion refusals. This grant applies only to
the new private station; the scanner has no shutdown privilege, and the change
grants no access to a shared service or interactive station. The subsequent
[native run](https://github.com/CharlesDerek/lab/actions/runs/40209982809) passed the
normal scanner launch with checked identity and job limits, assigned desktop,
cross-logon denials, final desktop cleanup and failed ownership-callback cleanup.
The network control also passed under the same reduced token before policy installation.
The subsequent [filter diagnostic](https://github.com/CharlesDerek/lab/actions/runs/40210991144)
found that BFE returned flags `0x41` for a filter created with `0x1`: it had added
`FWPM_FILTER_FLAG_INDEXED`. The verifier now ignores only that documented
[lookup metadata flag](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
Persistence, disabled/action flags, identities, weights and conditions still
must match. A regression test toggles every other flag bit for all ten rule
definitions, both with and without indexing, and requires rejection. Native WFP
enforcement and recovery of the corrected policy remain to be validated.

A fresh workspace contains copies of the executable, adjacent DLLs and flat
signature files, with a combined 768 MiB staging budget and at most 256 source
entries per directory. No recursive copy follows directory aliases. The staged
executable must match the pinned digest. The scanner gets read/execute access to
these copies and configuration, and access to a separate low-integrity scratch
directory on an owned fixed VHDX. The privileged worker has its own private temporary
directory. A private workspace journal records the volume and full 128-bit
directory ID before any file is staged. Startup reconciles retired workspaces
after launch/network recovery; normal shutdown does so after confirmed scanner
exit and release of every workspace pin. Unreconciled state stops admission.

The scanner job allows one process and caps process memory at 2 GiB. This
reduces privileges and protects private endpoint state; it is not complete
filesystem or IPC confinement. Public readable objects remain readable,
low-integrity public objects may remain writable. Dedicated scratch capacity
and workspace cleanup are implemented but require native validation. The volume
bound does not establish complete confinement of a compromised scanner.

Cleanup runs in a separately owned job with a 30-second parent deadline and
bounded stdin/output. The worker verifies its actual parent and LocalSystem
identity, and refuses to proceed while any launch/network journal remains.
Workspace journals are private atomic snapshots at
`STATE/protection/windows/workspaces/WORKSPACE_ID.json`. A mismatched directory
identity retains the journal. An absent root permits replay after a committed
deletion. Without a journal, only an empty reserved-name directory can be
removed; legacy nonempty workspaces require offline review.

The worker enumerates directories through handles in 16 KiB batches, preserving
exact UTF-16 filenames and 128-bit IDs. Each child is opened as one relative
leaf with no final reparse traversal, and its identity is checked against the
enumerated entry. Open handles deny write/delete sharing. Reparse leaves are
unlinked without descending into their targets; regular hard links are unlinked
without writing file data or changing shared attributes. Deletion is issued
on the same handle and the parent is flushed before proceeding. These operations
use Microsoft's [handle-based directory information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info),
[relative no-follow open contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile),
and [POSIX disposition contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex).

Cleanup bounds each tree to 32 levels below its root, 16,384 traversal steps and a
20-second cooperative deadline. OS I/O can exceed that deadline, which is why
the parent owns an independent worker job. Sharing conflicts, permission
failures, unsupported filesystem behavior or exhausted budgets leave the
remaining tree and journal for retry. New scanner admission waits for cleanup
to finish; cleanup does not relax ACLs to force deletion.

Before scanner launch, the supervisor journals a network policy derived from
the pinned staged image's WFP application ID, then installs ten persistent
filters and a private persistent sublayer in one transaction. The policy blocks
outgoing IPv4/IPv6 connections and incoming/listening traffic, with higher
priority exceptions for listening on the configured `127.0.0.1` port and
accepting TCP from `127.0.0.1` on that port. The listen layer is TCP-only and does
not expose a protocol condition; the receive/accept exception explicitly
requires TCP. Blocks match the image independently of the thread's user/group
token, so disabling a token group cannot make a block stop matching.
Additional connect rules match WFP's original application ID to cover socket
redirection through a proxy. Redirector-specific behavior still needs native
integration tests.
Process creation uses the same canonical executable path used to derive the
application ID, rather than an installer-provided short-name or drive alias.

The exceptions use soft permits so other security providers can still block
traffic. The objects grant administrative access only to SYSTEM and
administrators. Their provider field is empty: a custom provider without an
associated auto-start service can have its filters disabled on BFE restart.
This design uses [WFP transactions and persistent object lifetimes](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
the documented [layer condition sets](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer),
[filter flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0),
and [filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).

Startup reads back every filter and sublayer identity, action, condition,
weight, flags and policy digest. The worker rechecks the policy each second;
stale or failed checks stop protection and cause the parent to terminate its
owned scanner. Status includes `network_policy` and `network_checked_ms`, and a
status read also checks the actual WFP objects. These are configuration checks,
not a claim that native traffic behavior has been verified.

Rules survive filtering-session or supervisor process exit. On normal error
cleanup, rules are removed transactionally only after the original scanner and
its whole job have ended. Uncertain process cleanup or changed/partially missing
rules retain the journal for recovery. Journals live at
`STATE/protection/windows/network/POLICY_ID.json`; destructors never remove
network rules. The policy restricts direct
sockets; it does not prove isolation from IPC services that proxy network
requests, or from privileged WFP policy changes.

The schema-2 journal records a `prepared` launch before installing rules. The
scanner is created suspended, with job assignment applied during creation.
The supervisor verifies its token and durably records `owned`, including PID,
creation time and logon SID, before resuming the original thread exactly once.
A failed journal write never permits scanner execution. This ordering uses
Microsoft's [suspended process creation contract](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
and [ResumeThread suspension count](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread).

At restart, the supervisor holds both service leases and checks its process
reaper before reconciling up to 64 journal entries. A prepared record proves
that its scanner was never resumed. An owned record requires the original
process to have ended; the single-process job limit and refusal of breakaway
are part of this journal version's contract. Recovery checks a held process
handle and creation time, refuses live or unobservable owners, and never kills
a process from a saved PID. Legacy policy-only records require offline review.
Status reads also bind the live scanner to the saved ownership record.

Recovery verifies and removes a complete matching WFP set in one transaction.
An entirely absent set is safe to replay after an aborted installation or
committed deletion; partial, changed or disabled sets stop recovery. Only then
is the journal removed. Bounded, private temporary files left by incomplete
atomic journal writes are reclaimed without parsing them as launch authority.
Workspace reclamation follows successful network reconciliation in its own
bounded worker. Native scratch-capacity enforcement, BFE restart/reboot behavior and native execution
of both recovery paths remain release gates.

The supervisor pins protected directories and derives NT/DOS names from the
same handles. It rejects overlap with endpoint state, agent/scanner directories
and signatures. It launches ClamAV and the filter worker in separately owned
kill-on-close jobs, verifies process creation identities and the actual scanner
TCP connection, checks startup within a fixed deadline, and terminates the
owned work if a child exits or health stops advancing. Diagnostics stay bounded
in memory. Parent death closes its job handles; native cleanup behavior remains
to be exercised on Windows.

The private spool and health files live under `STATE/protection/windows`.
Management collection transfers malware and error decisions to its normal
durable outbox, retaining full Windows file IDs, actor creation times, hashes,
policy/session identities and NT paths. Response paths are derived from the
registered DOS scope; unknown scope, alternate-stream aliases and paths beyond
the event contract's budget fail admission visibly. Allowed opens are counted
by the driver rather than stored as malware evidence.

`windows-protection-status STATE/protection/windows`, run as LocalSystem, reads current status and
checks the scanner and worker process creation identities. The preview reports
`live_blocking_verified: false` and `scanner_isolated: false`. The separate
`scanner_identity_verified` field is set only after checking the actual process
token, and status reads recheck its creation identity and logon SID. Complete
scanner isolation is not claimed by that token check. The SCM host described
below owns the management launcher/controller; production prevention startup
and live blocking proofs remain unfinished. Protected quarantine now
has the development implementation described below; its native execution is
still unverified.
Durable kernel-loss accounting is implemented as described below; native driver
execution and end-to-end Windows validation remain required. Installer mutation now retains the shared
maintenance guard through setup and task registration, with durable startup
gates for interruption. Native execution of those installer, maintenance and
recovery paths remains unverified.

### Protected quarantine verification

When the private Windows protection state exists, a quarantine intent pins its
current session and policy. A missing or stale preview cannot silently select
the ordinary local reader. Restore and already-journaled recovery continue to
use retained evidence; recovery never repeats a source-open attempt or an
unconfirmed source rename.

The disposable mutation worker registers one ten-second correlation request in
the private spool before attempting its ordinary source read. It may attempt
source verification only once in its process lifetime. The request binds the
actual PID and process creation time, protected DOS path, volume serial, full
128-bit file ID, size, policy and client session. A successful ordinary read is
hashed locally. If Windows returns access denied, only an applied malware
denial for that exact attempt can supply the hash. Scanner errors, missing
evidence, changed identities, expired requests, conflicting decisions and
stopped/replaced protection sessions all fail verification. The approved hash
and current source metadata must still match before capture.

Denial delivery evidence and the response copy commit in the same SQLite
transaction. The response copy survives management delivery and process restart,
is consumed once, and has a separate 64-request bound. Expired requests are
reclaimed at admission. An interruption cannot turn a previous worker's receipt
into authority for a new worker. Cumulative coverage gaps remain visible;
successful verification of one exact receipt does not imply lossless coverage.

Capture opens the source for delete/rename and metadata access only. It checks
unsupported alternate streams before moving the file, then retains a separate
hash-verified copy in private quarantine. No new process exemption or kernel
operation was added. The rights distinction follows Microsoft's
[file access and sharing contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew);
stream checks use
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex).
Actual filter denial, metadata-only capture, post-rename access, restore while
protection stays armed and interrupted recovery still require Windows execution.

Health-file readers permit atomic replacement while retaining a handle to the
old private snapshot. Mutation journals retain their stricter filename pins.
Native tests cover this sharing contract, service locking, process identity and
bounded diagnostic draining; these tests are linked locally, not executed here.
Two additional ignored native tests require LocalSystem in service session zero:
`scanner_reads_copies_writes_scratch_and_cannot_read_private_state_or_change_engine`
checks real filesystem access under the restricted token, including refusal of
another logon's workspace and denial of scratch-file owner rights to an
unrestricted LocalService token; `scanner_launch_has_checked_identity_job_limits_and_owned_cleanup`
checks actual process creation, token identity, limits, output and termination.
They must pass explicitly with `--ignored`; ordinary CI must not count them as
executed. Real ClamAV startup and INSTREAM scanning under this token remain a
separate native integration gate.

The ignored native test
`windows_job::tests::scanner_network_rules_survive_owner_exit_and_allow_only_configured_loopback_service`
first runs a control probe under the same image and restricted token to prove
the host permits the tested operations. It then installs rules from a helper
that exits without running destructors and checks the retained rules from a
new session. A staged probe runs under the actual
restricted scanner token and job: outgoing IPv4, IPv6 and UDP plus forbidden
listeners must return `WSAEACCES`, while the configured loopback listener must
complete a real round trip. Changed-journal cleanup must be refused. Successful
cleanup follows confirmed job exit. The test keeps its temporary workspace and
prints its path; on failure, its private journal and scoped persistent rules
remain available for recovery. This test has been cross-linked, not run here.
It does not restart BFE or change global firewall settings.

The additional native gate
`protection::windows::recovery::tests::recovery_reconciles_aborted_installs_owner_crashes_and_committed_deletions`
exits a separate scanner owner without destructors at three points: suspended
before ownership persistence, owned before resume, and after actual scanner
output. It checks retained rules, reconciliation, interrupted journal writes,
deletion replay, refusal of live owners and refusal of legacy records. The
network fixture also injects a failed ownership callback and verifies that the
scanner never writes its output file. These tests are cross-linked only until
executed in a native LocalSystem session-zero environment.

Two native cleanup fixtures in `windows_state::cleanup::tests` exercise
hard links, external file/directory symlinks, alternate streams, read-only
attributes, raw UTF-16 names, held handles, changed IDs, root redirection,
empty-only orphan cleanup and budget refusal. The `windows_workspace`
integration test drives the actual agent worker through its stdin protocol in
an owned process tree, checking parent-spoof refusal, retained launch-journal
refusal and replay after root deletion. All three tests are ignored by default
and require an explicit native LocalSystem session-zero run. The link fixtures
also require symbolic-link privilege. Cross-linking does not establish these
filesystem behaviors.

Run this individual gate from an authorized LocalSystem session-zero test
environment, with native Windows Rust tools:

```powershell
cargo test --locked -p athernex-endpoint --lib windows_job::tests::scanner_network_rules_survive_owner_exit_and_allow_only_configured_loopback_service -- --ignored --exact --nocapture
```

## Durable evidence coverage

The current driver/client ABI is version 2, using `\AthernexScanV2` and a 96-byte
status response. Deploy the matching development driver and client together;
older protocol versions and missing driver identities are rejected. Client health
snapshots use schema 2; the plan and existing schema-1 denial receipts retain
their original formats. This does not authorize
an in-place production driver update or enable normal Windows protection.

Each driver load obtains an opaque UUID through
[`ExUuidCreate`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate)
before registering the filter. A UUID unique to that computer is sufficient for
this endpoint-scoped journal; an unavailable UUID fails driver initialization.
The instance stays unchanged across client connections and policy changes. Its
hashed identity and cumulative counters are checkpointed in the private evidence
database. This prevents reconnects from counting the same kernel drops again.

The worker durably records its session before starting the client. Kernel delivery
losses, local channel/spool losses and gap indicators remain separate. A driver
reload or interrupted worker records an unknown interval; unsampled losses from
the retired driver cannot be reconstructed. Regressing counters under the same
driver identity retain the earlier baseline, record a failure and stop the worker.
Stopping also records that the unsampled tail is unknown. Previously initialized
spools without coverage metadata retain a permanent `legacy_history_unknown`
marker. There is no reset command that can erase this history.

Kernel counters are driver-wide and may include earlier policies and unreported
error decisions; they do not count missing malware detections specifically. Gap
indicators can describe overlapping causes and do not count every lost event or
measure the duration of a gap. The status response includes `coverage` and the
derived `coverage_incomplete` flag. Neither counter continuity nor a connected
filter establishes live file blocking or complete scanner confinement.

Checkpoint updates and their immutable coverage notices commit together. The
notice spool holds at most 64 entries in addition to 2,048 denial receipts.
Exhaustion refuses further admission while retaining earlier records. The
management transfer journal covers both bounded sources and checks every retained
entry during cleanup, so an initial block of live transfers cannot hide retired
entries indefinitely. Local loss counters also commit with their notice; failed
transactions do not partially advance a counter or its checkpoint.

Management delivers subscription boundaries as inventory and observed loss/gap
notices as agent errors, with exact coverage details available through the
operator-authenticated endpoint export. Transfer records survive a server ACK
followed by a crash before source deletion. The portal does not turn these gap
records into malware detections or authorize a response action from them.

Portable tests execute the real spool, transaction and transfer logic, including
worker/driver identity changes, counter regressions, full queues, failed writes,
legacy migration and ACK recovery. A real HTTP endpoint/server fixture verifies
offline delivery, exact export and replay after server reopen on Linux. C ABI
checks and WDK compilation verify the new layout and imports. These are not native
Windows runtime tests: UUID generation, actual driver drops/reload, LocalSystem
lifecycle and Windows filesystem persistence must still be exercised on Windows.

## Maintenance and retired-state recovery

Agent/controller replacement, rollback and engine maintenance use the shared
`update::quiescent` guard. On Windows this always acquires the private
`protection/supervisor.lock`, even with `protection.enabled: false` and before
any preview state exists. Its held directory handles reject reparse paths and
prevent namespace replacement. A preview cannot race the first maintenance
check by creating its directory later. If `protection/windows` exists, the guard
also retains its supervisor, client and scratch-worker leases.

New shared lease objects created by LocalSystem use SYSTEM ownership. Elevated
administrator creation uses Administrators ownership; both grant access only to
SYSTEM and Administrators. This avoids leaving a personal account grant that
the service's strict private-state checks would reject later. Existing objects'
permissions are validated without being rewritten, and per-user installations
keep their own private identity. Native owner/ACL fixtures still need execution
under both service and elevated administrator accounts. See Microsoft's
[new-object ownership contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object).

Maintenance refuses any remaining entry in `network`, `scratch-journal`,
`scratch-runtime`, `scratch-health`, `workspaces` or `runtime`. It preserves the
entry without interpreting an incomplete record as proof of termination. Old
client health and durable evidence can remain after ownership has been retired.
The guard stays alive across executable/engine mutation and is reacquired after
a runtime trial. The installer uses `windows-install BUNDLE_DIR AGENT_DIR
STATE_DIR` in the bundle executable to retain the launcher, controller, endpoint,
native protection and update leases through executable replacement, enrollment,
antivirus provisioning and SCM service registration. Enrollment and
provisioning run in process, so enrollment can use the installer's already-owned
state database without dropping its lock. `installer-check --stopped` remains a
readiness snapshot; the PowerShell installer delegates mutations to the retained
Rust guard instead.
Standalone Windows enrollment/provisioning also retains `installer.lock`, so it
cannot enroll a fresh identity while an installer records its initial intent.

The private `installer.json` records the source digest, server, destination and
state volume/full file ID. A pending or malformed journal blocks normal
launcher/controller/agent startup and ordinary executable/engine maintenance.
Rerunning the same bundle resumes a valid pending installation with its retained
identity. Only the initial `preparing` phase permits creating a configuration;
`installing` or `complete` with a missing configuration requires restoring that
configuration. Reinstallation of an existing endpoint enters `installing`
directly. Existing signed update ledgers are checked again under ownership, and
local executable destinations must agree with the installer. A different source,
origin, destination or state identity cannot silently resume a pending install.

Executable replacement and installer/configuration journals use atomic writes
with explicit SYSTEM/Administrators permissions. The service is registered while
the guard is held; readiness is committed only after provisioning, registration
and owned-child cleanup succeed. The outer PowerShell script starts the service
after the coordinator exits successfully, waits for SCM `Running`, and then
removes the bootstrap. SCM state does not prove antivirus readiness. Errors
retain the bootstrap and pending journal for retry. This does not make package
manager work transactional: an interrupted MSI installation can leave changes
or delegated work that must settle before retry.
Windows antivirus downloads are staged inside the private, pinned
`installer-packages` directory, rather than an interactive user's temporary
directory. Nonempty staging refuses another download. After a crash, finish or
repair the Windows Installer transaction and remove only confirmed retired
packages before retry; the endpoint does not infer that delegated MSI work has
terminated or discard those files automatically. Staged MSI files also receive
explicit SYSTEM/Administrators permissions, independently of inherited ACLs.

Installation requires an elevated administrator, separate local directories,
existing parent directories and private existing state/executable directories.
Existing directory owners/grants must be SYSTEM or Administrators, with full
access for both identities; privacy to the installing user alone is insufficient.
It never silently rewrites an existing directory's ACL. Older installations with
inherited public read access to the executable directory need an explicit,
reviewed permissions migration before this installer can replace them. Native
first-install, upgrade, interrupted MSI, reboot and service-start validation
remain required; cross-compilation is not evidence that those paths work.

After stopping the preview, run from a LocalSystem shell on the native test host:

```powershell
athernex-endpoint.exe windows-protection-recover C:\ProgramData\AthernexEndpoint
```

This command acquires the common and native supervisor leases, refuses a live
filter client or scratch helper, then reconciles scanner/network ownership,
reclaims detached scratch storage and retires staged scanner workspaces in that
order. It uses the existing bounded cleanup workers and preserves uncertain
state for retry. It never starts protection, loads a driver, adopts an existing
disk or terminates a PID from a journal. Successful completion emits
`{"schema":1,"recovered":true}`. Repeating completed recovery is harmless.

Preview startup uses the same recovery sequence under its leases. It now reads
configuration and checks settled agent/controller/engine transactions after
acquiring exclusion, preventing startup against an interrupted replacement or
an in-progress runtime trial. These checks do not enable normal Windows
protection or provide native installation validation.

Windows tests cover first-start exclusion, every worker lease, namespace pins,
retention of each recovery directory, disabled-policy update/installer checks
and release/reacquisition of the maintenance guard. Installer fixtures additionally
cover retained ownership across setup, pending-journal startup gates, source/state
binding, missing-configuration rejection and SYSTEM-compatible atomic writes.
`tools/test_windows_installer.py` executes the production PowerShell scripts with
mocked commands to check ordering, failure propagation, exact service ownership,
quoted service arguments and legacy-task migration;
it does not install a service or prove Windows SCM behavior. The ignored
`actual_preview_recovery_waits_for_workers_and_retires_scratch_before_staged_files`
integration fixture runs the real executable with only private partial-image
and staged-file records; it requires LocalSystem and performs no disk attachment,
formatting or driver installation. These fixtures have not been executed here.

## Windows service lifecycle

The Windows installer now registers the stable launcher with Service Control
Manager as `AthernexEndpoint`, an automatic LocalSystem service. Its command is
`athernex-launcher.exe windows-service STATE CONTROLLER AGENT`. The host starts
the existing `launch` command in an owned kill-on-close job; the launcher retains
its existing ownership of the controller, management agent and their jobs.
`SERVICE_RUNNING` describes this host, not successful enrollment, detection or
native prevention. Normal Windows prevention activation remains gated.

The control callback changes state and returns without disk access or waiting
for children. The worker handles stop/shutdown and allows 15 seconds to confirm
that the entire owned job and any process-creation reaper have finished. It
retains `STATE/windows-service.lock` throughout cleanup; the installer acquires
the same lock before modifying executables. A stop cannot be overwritten by a
late running report, and the terminal SCM status is published only once, after
owned resources have been released. Unconfirmed cleanup exits the host as a
failure without claiming a clean stop. The OS closes the job handles; existing
endpoint leases/journals still govern recovery if termination is incomplete.
Lifecycle diagnostics are bounded and saved in
`STATE/supervisor/windows-service.json`; they are not a heartbeat.

This follows Microsoft's [dispatcher startup contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw),
[control-handler contract](https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function)
and [terminal-status rules](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus).
SCM restarts failed hosts after 60 seconds. The service owner is Administrators.
Ordinary authenticated users receive query/interrogate access; SYSTEM and
Administrators retain service control.
This is not a protected antimalware service, ELAM integration or resistance to
a hostile administrator.

Migration checks the exact existing service command, account and service type
before stopping it. It checks the old scheduled task's single executable/action
before disabling and stopping that task. Registration refuses unrelated or
still-running services and removes a matching, stopped legacy task only after
the new service configuration succeeds. Installation errors retain the bootstrap
and durable pending journal. Native migration, reboot, delegated MSI work and
release recovery remain unverified.

On an explicitly disposable Windows host with **no existing Athernex service or
task**, the following fixture runs from a LocalSystem session-zero shell:

```powershell
tools\verify_windows_service.ps1 -DisposableHost `
  -Agent C:\private\athernex-endpoint.exe -AgentSha256 <exact-lowercase-sha256>
```

It prepares private executable copies and an offline endpoint, then uses the
production registration script. Six native checks cover registration, the actual
host/launcher/controller/agent tree, installer exclusion, clean stop, explicit
restart, and host-crash cleanup with SCM recovery. Process handles and creation
identities distinguish owned descendants from reused PIDs. Cleanup checks the
exact service command before removing only the fixture's service; files and its
report remain private for review. It installs no antivirus or driver and makes
no prevention claim. All six checks passed on the hosted Windows Server 2022 VM
at commit `62a4e27d`; see the hosted service lifecycle results below. This does
not cover production installation, migration, reboot or signed prevention.

## Dedicated scratch disk development

`endpoint-native/src/windows_scratch/` and the preview's `windows/scratch/`
implement dedicated temporary storage. The supervisor starts an owned scratch
worker before ClamAV, checks its committed readiness, and directs ClamAV's
`TemporaryDirectory`, `TEMP` and `TMP` to its volume GUID path. **Native Windows
execution remains unverified; this integration does not enable production
protection or establish antivirus replacement.** There is no directory-storage
fallback after disk creation or validation fails.

The new API accepts a fresh, empty private container and a 256 MiB–4 GiB capacity
in whole MiB. It creates a fully allocated VHDX, checks its identity, provider,
fixed subtype and exact virtual capacity, and limits observed backing-file
overhead to 64 MiB. Creation requires an additional 128 MiB free-space reserve.
No existing image can obtain the initialization capability. Inspection of an
existing image is read-only, refuses parent chains, and requires matching
identity/capacity and an unattached state; this observation alone is not deletion
authority.

Attachment has no drive letter or permanent lifetime. `SeManageVolumePrivilege`
is enabled on a temporary thread impersonation token and reverted afterwards.
The physical device name comes only from the owned VHD handle. Initialization
checks that device's number and capacity, requires a raw disk, and changes GPT
through the held device handle. A session-derived GPT identity, bounded usable
range and observed MSR arrival precede the final layout. Discovery accepts one
volume GUID root with the exact data-partition ID and single disk extent. The
formatter receives this descriptor through bounded stdin in a separately owned
PowerShell job. It imports Windows' Storage module, resolves the exact volume
object, checks its partition GUID, disk number, offset, length and non-boot state,
and refuses an existing filesystem. Only that verified object is passed to
`Format-Volume`, using NTFS and 4 KiB clusters. No formatting command selects a
drive letter or disk number. These operations do not change host-volume quota
policy.

After formatting, native checks independently verify the volume binding, NTFS,
allocation unit and capacity. The fresh volume root receives SYSTEM/admin-only
permissions and is held exclusively. A newly created low-integrity scratch child
grants its scanner logon create/list/traverse rights on the directory and Modify
on descendants. Its held handle denies write/delete sharing, preventing the
root from being reopened for reparse-point changes or replacement. Actual
owner, DACL, mandatory label, file identities and capacity are checked again in
the worker's heartbeat. This preserves the existing strict private-state path
contract; arbitrary volume GUID paths cannot be opened as general private state.

The private `scratch-journal/ID.json` record contains the container's volume and
128-bit directory ID, disk specification, scanner logon, worker PID/creation
time, and an image-ready phase. Ownership is committed before creation and the
image-ready phase before attachment. A global scratch-worker lease excludes
duplicate helpers and cleanup. Startup waits at most 180 seconds; formatting has
its own 60-second job deadline. Private `scratch-health/ID.json` snapshots must
advance within five seconds and match the owned process, storage and scanner
logon. Missing, changed or stale health stops the scanner.

Retirement waits for scanner termination and network reconciliation, then
requires the original scratch worker to have ended. A bounded cleanup job
checks recorded container identity and, for a completed image, read-only
detached-image evidence. Exclusive handle-based deletion must also succeed.
Partial pre-attachment images can be reclaimed after their recorded owner has
ended; corrupt completed images are retained for review. Unknown nonempty
containers, live/unobservable owners and mismatches retain their journals.
Root-deleted/journal-retained cleanup can replay. Recovery never initializes,
formats or reattaches an existing image.

See Microsoft's [fixed VHD creation contract](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk),
[attachment lifetime flags](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/ne-virtdisk-attach_virtual_disk_flag),
and [GPT initialization and MSR arrival requirement](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_create_disk).
Formatting uses Microsoft's [volume-object operation](https://learn.microsoft.com/en-us/powershell/module/storage/format-volume),
followed by [handle-based filesystem queries](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile).

Portable tests cover capacity/range overflow, independent session/object
identifiers and rejection of drive, device, network and descendant formatting
paths, canonical logon SIDs, and filesystem capacity/overflow checks.
`tools/test_windows_scratch_formatter.py` executes the real script against a
fake Storage module: 29 scenarios cover successful acknowledgement, malformed
requests, changed GUIDs/extents, drive letters, existing filesystems and bad
format results. It never formats a disk. Local PowerShell 7 results do not prove
Windows PowerShell 5.1 behavior; the Windows workflow runs this same fixture with
the production interpreter.

Opt-in `windows_scratch::tests` fixtures cover fixed allocation, refusal
to adopt existing content, changed identities, attached-image recovery refusal,
GPT/volume provenance, thread impersonation cleanup and attachment-owner exit
without Rust destructors. They create only fresh private images and leave
evidence on failure. They require LocalSystem on a disposable Windows host,
with `--ignored --test-threads=1`; they have not been executed here. Native MSR
arrival and attachment cleanup remain release gates. The endpoint fixture
`protection::windows::scratch::tests::owned_worker_formats_bounds_scanner_writes_and_recovers_only_after_exit`
runs the real worker and formatter, fills a fresh 256 MiB volume under the
restricted scanner token until native disk-full, checks another logon's refusal
and scratch-root write/rename denial, and verifies recovery ordering and replay.
It has been cross-built, not executed. Real ClamAV volume-path compatibility,
low-space behavior, crashes during each storage phase, reboot recovery and native
permissions/sharing behavior still need validation.

The `windows_workspace` integration target also exercises the actual agent's
`windows-scratch-cleanup` command with an incomplete private image. It checks
parent binding, worker-lease and live-owner exclusion, scanner recovery ordering,
nonce-bound acknowledgements and interruption replay. This ignored fixture
requires LocalSystem and never attaches or formats a disk. It remains unexecuted
on Windows.

## Reproduce the development build

Python 3.12, Clang with the MSVC target, and LLD are required. The tested local
compiler is Clang 21.1.8. The helper verifies exact package size and SHA-256
before extracting selected files from Microsoft's WDK/SDK NuGet packages,
version `10.0.26100.6584` (headers/library version `10.0.26100.0`). It installs no
host packages. Package pins are in `tools/prepare_windows_filter_kits.py`.
See [Microsoft's NuGet WDK instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget).

```sh
python3 tools/prepare_windows_filter_kits.py \
  --output /tmp/athernex-filter-kits \
  --package-cache /tmp/athernex-filter-packages
python3 tools/build_windows_filter.py \
  --wdk /tmp/athernex-filter-kits/microsoft.windows.wdk.x64/c \
  --sdk /tmp/athernex-filter-kits/microsoft.windows.sdk.cpp/c \
  --clang /absolute/path/to/clang \
  --linker /absolute/path/to/lld-link
```

The output defaults to `.athernex/verification/windows-filter-build/` and includes
an unsigned `athernex-filter.sys` plus `build.json` containing source hashes,
compiler/linker versions, binary hash and an explicit false runtime-validation
flag. The build does not supply an INF, invent an altitude, alter boot policy,
install a service, or sign/load the driver.

`.github/workflows/endpoint.yml` includes a Windows development build job, the
native Rust platform tests, Linux execution of the C protocol validators, and
the real-ClamAV stream fixture. Development artifacts are separate from the
portal's installer catalog.

Hosted Windows Server 2022 validation at commit `1878125e` passed native Rust
tests, evidence sealing/backup recovery, enrollment/response/restart recovery,
signed agent and controller replacement with forced-crash recovery, and automatic
agent installation/runtime rollback on 2026-10-25. The
[platform job](https://github.com/CharlesDerek/lab/actions/runs/40197329277/job/121180895775)
then failed at launcher-owned controller maintenance because its ownership lease
was not established. The later full Windows platform job at `62a4e27d` passed,
including controller delivery, both fleet rollouts and native SCM lifecycle.
Real minifilter authorization remains unverified. Earlier local verification
records below retain their original scope.

## Verification and release gates

Local verification includes a WDK-linked driver build, Windows Rust test linking,
Linux Rust tests, Clippy checks for Windows and both macOS architectures, and
20,000 adversarial inputs through the actual C protocol validators under ASan
and UBSan. The isolated Linux ClamAV fixture verifies clean/detected whole-stream
results and exact hashes. It does not run Windows APIs or prove blocking.

```sh
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer infrastructure/endpoint/windows-filter/test_wire.c \
  -o /tmp/athernex-filter-wire
/tmp/athernex-filter-wire
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 \
  cargo test --locked -p athernex-endpoint-native
python3 tools/verify_windows_filter_transport.py \
  --engine-prefix /absolute/path/to/verified/engine/usr/local
```

The stream fixture requires the same isolated Docker image and verified engine
as the Linux native protection fixtures. It uses a private benign signature,
network isolation, a read-only container and bounded resources.

Before enabling Windows prevention in installers or reporting `realtime: true`:

1. Validate the implemented update exclusion and retired-state recovery on
   Windows, retain exclusion across installer mutations, integrate production
   prevention startup with the SCM-owned controller, validate the reduced scanner identity and complete
   native scratch-capacity enforcement/IPC confinement and native crash-cleanup validation, validate native network policy, add live blocking
   proofs, and validate protected response access and persisted kernel loss
   across reload.
2. Complete coverage for existing handles and executable/mapped content; define
   supported filesystems, file types and maximum sizes as product policy.
3. Exercise actual Windows allow/deny behavior, cancellation, disconnect,
   reconnect, policy changes, concurrent writes, directory replacement,
   low-memory/disk failures and reboot recovery. Run Driver Verifier and the
   applicable compatibility/performance tests on disposable native hosts.
4. Obtain the appropriate assigned minifilter altitude and production signing,
   then package and validate native installation, upgrade, rollback and removal.
   See [Microsoft's altitude allocation guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes).
5. Validate detection quality, false positives, update reliability and platform
   protection behavior before offering replacement of an existing AV product.

These remain unfinished requirements, not checks waived by compilation.


## Evidence coverage checkpoint (2026-10-24)

- Implemented durable driver-instance counter checkpoints, separate local/kernel
  loss totals, interruption/reload markers, immutable bounded notices and recovery
  after management/server ACKs. The full-journal recovery test also verifies that
  live entries cannot hide retired transfers and starve new coverage delivery.
- Passed 199 endpoint, native-support and protocol tests on Linux; 11 explicit
  native fixtures remain ignored in that run. The real HTTP fixture preserved
  all original coverage notices through offline delivery, authenticated export
  and server reopen/replay without creating malware cases. The final focused
  evidence suite passed all ten tests, including Unicode-safe failure reporting.
- Strict Linux workspace and Windows cross-target lint passed. The unsigned x64
  driver built against Microsoft WDK/SDK 10.0.26100.0, and the C ABI validators
  passed under address/undefined-behavior sanitizers. The Windows agent and both
  library test executables linked successfully; none were executed on Windows.
- The paired development build and its hashes are retained under
  `.athernex/verification/windows-coverage-build/` and
  `.athernex/verification/windows-coverage-driver/`. The verification record is
  `.athernex/verification/windows-coverage-validation.json`.
- Actual driver UUID/counter behavior, native blocking, LocalSystem service
  lifecycle, protected response, scanner confinement and platform signing remain
  required. Normal Windows protection activation and the original multi-platform
  completion claim remain gated.

## Protected response checkpoint (2026-10-24)

- Implemented the single-attempt denied-read verifier, atomic response/evidence
  retention, bounded expiry and metadata-only capture described above. Production
  activation remains disabled; there is no new minifilter exemption or ABI change.
- Passed 206 endpoint, native-support and protocol tests on Linux, with 11
  explicit native fixtures ignored. The final 17-test evidence suite includes
  seven new response tests for identity mismatches, scanner errors, session
  changes, old evidence, replay, expiry/capacity and transaction rollback.
- Two additional Windows filesystem tests exercise the metadata-only capture
  sharing contract and verifier/recovery integration. They are cross-linked,
  not executed. No native Windows blocking or quarantine claim is made.
- Verification and development artifacts are retained in
  `.athernex/verification/windows-response-validation.json` and
  `.athernex/verification/windows-response-build/`.

## Native prevention and response fixture

The ignored `native::native_windows_protection_and_response` integration test
in `core-engines/endpoint/tests/windows_mutation/native.rs` drives the actual
preview, ClamAV, minifilter, management HTTP loop and mutation worker. Run it only
on a disposable native Windows host as LocalSystem in session zero, with a
private ClamAV installation and an already loaded ABI2 driver. The driver must
be unarmed and have no other client. The test does not install or load a driver,
change signing policy, or replace an existing protection policy.

```powershell
$env:ATHERNEX_NATIVE_WINDOWS_FIXTURE = '1'
$env:ATHERNEX_WINDOWS_CLAMD = 'C:\AthernexNative\ClamAV\clamd.exe'
cargo test --locked -p athernex-endpoint --test windows_mutation native::native_windows_protection_and_response -- --ignored --exact --nocapture
```

For a copied test executable, also set `ATHERNEX_NATIVE_AGENT` to the matching
agent executable and invoke the same exact test name. The fixture copies that
agent into private state and records its SHA-256. A ten-minute owned process
job bounds the scenario. It creates a 256 MiB scratch VHDX and the preview's WFP
rules through the production preview code. It retains the unique fixture root,
input specification, bounded diagnostics and `state/native-validation.json`,
including on failure. It stops only its own preview and disarms only the same
driver instance and fixture policy, then runs native journal recovery. An
unexpected owner, changed policy, cleanup failure or timeout retains the state
for review; the fixture never unloads the driver or deletes unknown resources.

Before activation, clean and synthetic targets must be readable, executable and
mapped as appropriate. The synthetic executable is a benign copy of the test
runner with a unique overlay and a whole-file SHA-256 signature; it only runs a
named child that prints a marker. After activation, clean controls must continue
to work. Each negative probe requires both Windows access denied and its exact
applied malware receipt, bound to actor PID/creation time, full file identity,
scope, policy/session, size, hash and signature. The fixture separately checks
new reads, execution, existing-handle reads, newly created mappings from existing
handles, reads from existing mapped views, and content changed after a clean
open. Missing checks or receipts cannot produce a successful overall report.

The scenario continues after unsuccessful blocking checks to exercise quarantine,
committed recovery without replay or receipt replacement, restore, and a fresh
denial of the restored file's new identity. It also verifies that the original
filter session remains active before cleanup. The current driver only enforces
file-open decisions: based on that implementation, the existing-handle/mapping
and post-clean-write checks are expected to remain unsuccessful. This fixture
has not been executed on Windows, and compiling it does not resolve those gaps.

The synthetic signature preconditions can be tested independently on Linux:

```sh
python3 tools/verify_windows_native_samples.py \
  --probe-executable /absolute/path/to/windows-mutation-tests.exe \
  --engine-prefix /absolute/path/to/verified/engine/usr/local
```

This uses the isolated native-test container to scan the PE as data, with no
network or Windows execution. ClamAV must accept the clean binary/data and
produce the exact two fixture detections for their synthetic counterparts.
The binary sample prefix avoids text preprocessing described in
[ClamAV's hash-signature contract](https://docs.clamav.net/manual/Signatures/HashSignatures.html).
Windows mapping probes use
[CreateFileMappingW](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw),
[MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
and [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
so an inaccessible view is reported as an operation error. Such an error alone
never counts as a malware denial.

## Hosted service lifecycle validation

The Windows matrix in `.github/workflows/endpoint.yml` now invokes
`tools/verify_windows_service_ci.ps1` after building the native executable. This
runner requires `-DisposableHost` and a GitHub-hosted Windows environment. It
copies the executable and fixture scripts into a new SYSTEM/Administrators-only
directory, verifies the copied executable hash, and starts one uniquely named
LocalSystem task. The fixture independently requires LocalSystem in session zero
and refuses an existing Athernex installation.

The service gate also runs after unrelated post-build fixture failures when the
native build, installer syntax, installer control-flow tests and service-runner
tests passed. Cancellation prevents it from starting. Earlier test failures
still fail the overall job.

The task has a bounded execution time and the workflow has a ten-minute limit.
Passing requires a successful task exit and all six native SCM checks, the exact
agent hash, LocalSystem identity and session zero in the report. An initial Ready
task state, missing report, skipped check or cleanup error cannot pass. Cleanup
disables and removes only the owned task; changed or unconfirmed task ownership
is retained as a failure. A timeout can leave the service fixture behind on the
disposable VM and never proves successful service cleanup.

The workflow uploads `service-validation.json`, `service-validation.log` and
`runner.json` even when the step fails. The first report also remains in the
fixture's private ProgramData directory. The runner report records the build
hash and GitHub run/commit identity. These reports cover service registration,
the owned process tree, installer exclusion, stop, restart and crash recovery;
they do not certify minifilter enforcement, signing or hostile-administrator
resistance.

The [hosted Windows platform job](https://github.com/CharlesDerek/lab/actions/runs/40205131600/job/121204327964)
passed all six native SCM checks at commit `62a4e27d` on 2026-10-25. The retained
`native-windows-service` artifact binds the report to the exact executable hash,
commit and run, and records LocalSystem in session zero. Registration, owned
descendants, installer exclusion, complete stop, explicit restart and host-crash
cleanup with SCM recovery passed. This is disposable-host service lifecycle
evidence; signing, prevention, production migration/reboot and hostile-admin
resistance remain separate open requirements.

The runner uses Microsoft's [service-account task principal](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal)
and [bounded task settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset).
The host restriction follows GitHub's [runner environment variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
and [disposable Windows runner model](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Hosted isolation validation

The independent `windows-isolation` job runs six existing opt-in tests through
`tools/verify_windows_isolation_ci.ps1` as LocalSystem in session zero. They cover
the scanner's restricted identity and job limits, private-state and engine access
controls, workspace cleanup with external links and pinned files, partial scratch
image recovery, and image-scoped WFP enforcement with a working loopback control.
These tests do not load a driver, attach a disk, or format a volume.

The runner stages only the two compiled library test executables in a new private
directory. SHA-256 hashes bind the input manifest and each execution. Each exact
test must appear in the ignored-test listing, exit successfully, and report one
executed success. The final report must contain all six checks and the expected
native account, session and input-manifest hash. Missing, filtered or skipped tests
cannot satisfy the gate. A bounded owned task and disposable VM contain a stalled
fixture; failures retain scoped WFP/workspace journals for inspection and do not
prove successful cleanup.

Only fixture reports and logs are uploaded; staged executables and private
workspace contents are excluded. Local runner tests validate evidence rejection
and task cleanup using mocked commands. The [hosted run at `0f0b88b`](https://github.com/CharlesDerek/lab/actions/runs/40203647817)
passed the private-state/engine access test, both workspace cleanup tests and
partial scratch image recovery as LocalSystem. Scanner startup and the WFP
control probe failed while loading runtime DLLs; network enforcement is still
unverified. The complete six-check gate has **not passed**. This gate does not establish signed
minifilter prevention, complete scanner confinement or hostile-administrator
tamper resistance.
