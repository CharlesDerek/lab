# macOS authorization adapter development

`core-engines/endpoint-native` contains a development Endpoint Security adapter
for macOS 12 or later. It subscribes to file-open, execution and file-backed memory
mapping authorization and sends the selected regular file's bytes to ClamAV over
a private Unix socket. It can be included in portal installers as an optional, signature-verified
build component. The endpoint controller now manages the scanner and adapter
together when local protection policy is enabled. The installer prepares the
dedicated scanner account, private runtime and signature database. Automatic
health now requires live clean controls and matching native denial receipts for
every protected root. **This implementation has not been executed on a Mac.**
A successful subscription or build cannot establish verified prevention.

## Authorization and evidence

Callbacks enqueue at most 64 retained requests without file or journal I/O. Four
scan workers read files through directory descriptors without following symlinks.
They verify the original device/inode, length and modification/change timestamps
before scanning, after scanning and after receiving the verdict, then reopen the
path to reject replacements. SHA-256 covers exactly the bytes streamed to ClamAV.
There is no verdict cache. Files larger than 128 MiB, malformed scanner responses,
changed files and scanner errors are denied for requests reaching this adapter.

The response loop owns the Endpoint Security client and answers pending messages
independently of the workers. It denies expired work at the earlier of the configured
100–5,000 ms deadline and Apple's deadline minus a 50 ms response margin. A late
worker result cannot generate a second response or allow an expired request. This
design still needs native load testing: a starved process or missing subscription
cannot enforce these guarantees.

Only configured roots are scanned. The adapter's exact process and the configured
dedicated scanner UID are exempt, as are nonregular files. Apple's default muted
process paths are retained and listed in status. Apple recommends preserving these
critical-process exclusions for system stability; they are a coverage limitation.
See [Apple's client contract](https://developer.apple.com/documentation/endpointsecurity/es_new_client(_:_:)).

Denials produce versioned private JSON receipts with the operation, requesting
PID/UID and PID version, original file identity, error or detection, and exact
streamed hash when a verdict is available. `response_delivered` records whether
Apple accepted the authorization response; a detected file does not by itself
prove that access was blocked. Each receipt has an immutable random ID and a hash
of its authorization policy. Receipts are capped at 4 KiB. The journal has a
128-record queue and a 2,048-file disk limit. A single process owns each native
state directory, and receipt publication refuses to overwrite an existing ID.

Queue/disk failures and immediate callback denials increment the dropped-evidence
counter. Status also records deadlines, response errors, event-sequence gaps and
changed watched-root identities. The adapter now checkpoints cumulative evidence
loss, response errors, sequence gaps and scope losses across process lifetimes.
Native execution and tamper resistance remain unfinished.

### Durable coverage checkpoints

Before subscribing, the adapter holds `native.lock` and atomically publishes
`authorization-coverage.json` with a random session ID, persistent lineage,
policy hash, PID/PID version, revision and cumulative counters. Its journal samples
the process counters once per second. Totals cover the lineage, including earlier
policies; the policy hash binds the current session. Publication syncs the file, renames it and
syncs the parent directory. A restart retains the last durable totals and adds an
unobserved interval: events after the last checkpoint and between subscriptions
cannot be reconstructed. Those intervals do not invent a count of missing events.
An existing development installation without a checkpoint retains an explicit
unknown-legacy-history flag. Invalid checkpoints prevent adapter startup.

The checkpoint is bounded to 8 KiB. Heartbeats update freshness separately from
immutable evidence revisions. Revisions change on subscription, restart, loss or
scope changes; the endpoint atomically transfers each observed revision to its
bounded SQLite outbox and records the accepted revision. A full outbox retains the
previous accepted revision. Later polls may coalesce intermediate observations,
but the latest checkpoint retains cumulative totals, session counts and unknown
intervals. This is sampled coverage evidence, not a journal of every transition.
Acknowledgement and endpoint restart cannot duplicate an accepted revision.
Changed revisions, regressing totals, replaced lineage, missing previously
observed checkpoints and foreign policy/state bindings are rejected.

Coverage events preserve the complete immutable evidence as inventory or
`agent_error` observations without actionable file hashes. The actual agent/server
fixture verifies offline delivery, exact evidence preservation and repeat polling
without extra malware cases. These fixture results use controlled checkpoints on
Linux; they do not exercise Apple's event stream.

Live blocking proof requires a fresh checkpoint from the matching subscription,
valid scope and no current-process evidence errors. Historical loss remains
separate: endpoint protection health reports degraded coverage and retains dropped
receipt totals even while the adapter is starting or its heartbeat is stale.
Restart intervals and historical loss are never cleared by successful probes.
The standalone blocking-proof field can therefore be verified while overall
endpoint coverage remains degraded. Checkpoint write failures invalidate fresh
coverage health without deliberately removing the authorization subscription.
Private files and monotonic checks do not resist a hostile administrator who can
replace both producer state and the endpoint database.

## Durable endpoint integration

For an enrolled endpoint, use `STATE_DIR/protection/native` as the adapter's
`state`. Its journal writes receipts to `verdicts/` and retains private policy
snapshots in `policies/<SHA256>.json`. The policy directory is capped at 64 entries;
retain scopes referenced by pending receipts and the current coverage checkpoint
before archiving old snapshots. The
endpoint consumes up to 64 receipts per cycle. It rejects untrusted permissions,
symlinks/special files, oversized/invalid receipts, mismatched IDs or scope hashes,
and evidence belonging to another endpoint state.

Each transfer commits the complete receipt and its verified detection/hash to the
endpoint's SQLite outbox before removing the source. A bounded transfer journal
survives a crash between those operations, including a server acknowledgement
before source cleanup. Unlinking is followed by a directory sync before the
transfer record is reclaimed. Capacity/validation failures retain the source and
report degraded collection health. Old scopes remain usable for queued evidence
after policy changes; actions still recheck the current endpoint action roots.

Verified detections enter existing malware investigations and can feed the
configured exact-hash quarantine playbook. Scanner errors enter `agent_error`
evidence without an actionable hash. The complete receipt remains in the event's
`detail` JSON and case exports. Ingesting a receipt never sets real-time health.
Legacy, unversioned development receipts are refused explicitly.

The Unix integration test uses a controlled receipt fixture and an actual TCP
agent/server connection to verify offline delivery, server restart, automatic
exact-hash quarantine and original receipt export. It does not run Apple's API.
The trusted response broker described below is now connected to scan and
quarantine actions. This receipt-delivery fixture does not validate a response
against a file actively blocked by Endpoint Security.

## Protected-file response broker

After subscribing successfully, the macOS adapter starts an owner-only Unix
socket at `STATE_DIR/protection/native/response.sock`. Broker workers run inside
the adapter's exact exempt process; the management agent does not get a scanning
exemption. Each request must match the pinned policy hash and selected roots.
The server and client verify kernel-reported peer UIDs in addition to private
filesystem permissions. Replies must match a fresh request nonce and the policy
hash. They return a hash and scanner verdict, never file contents or arbitrary
command execution. The implementation uses Apple's
[peer-credential interface](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
on macOS and `SO_PEERCRED` on Linux.

Two dedicated workers and an eight-connection queue bound response work separately
from the authorization workers. Request/reply frames are capped at 8 KiB, incomplete
requests have a two-second read deadline, and client operations have a maximum
30-second socket deadline. A filesystem stall can occupy a worker but does not
extend the client's socket deadline. Scans bind the opened file's identity and
hash exactly the bytes sent to ClamAV; each file is limited to 128 MiB. Replaced
roots, scope failures, scanner failures and expired work cannot yield a successful
hash response. There is no verdict cache.

The persistent private `response.json` binding makes a missing or stopped broker
an action failure; the agent does not silently fall back to direct reads. A lock
excludes duplicate brokers and permits removal of a stale socket after a crash.
Removing the binding is an explicit local deconfiguration step after stopping the
native service and restoring the intended scan configuration.

Approved scans use the broker when this binding is present. They retain the local
action-root checks and limits of 4,096 entries, 32 directory levels and 1 GiB total
scanned bytes. A separate instance of the installed endpoint executable resolves
paths, walks directories and queries the broker. It receives a bounded request
through a private stdin pipe, without server credentials or a database handle.
The parent validates a complete, request-bound report (at most 1 MiB) before
committing evidence atomically. Failed, interrupted or timed-out workers cannot
commit partial detections. The helper also handles broker hash requests.

On Linux and macOS, the process runner uses bounded nonblocking pipes and requests
process-group termination at the action deadline. It waits at most another 100 ms
for cleanup, then retains the child in a bounded background reaper. Unreaped
children and remaining process groups keep their capacity slot; at most 16 managed
commands/services can be outstanding in one calling process. Each bounded command
adds one independent watcher process. A leader exit with unresolved group cleanup
fails the action instead of reporting success.
A kernel-uninterruptible operation may outlive a kill request, so pending cleanup
is reported rather than claimed complete. The leader remains waitable until the
group is signalled, preventing signals to a recycled leader PID. Internal workers
bind to their parent using Linux parent-death signalling or a macOS process-exit
watch. macOS runtime validation of that watch remains required. Agent state and
the installed helper must be on trusted local storage; this does not preempt
blocked agent database I/O or executable loading.

Native-broker quarantine and restore now run in separate supervised mutation
workers. The agent commits intent to SQLite before starting the worker. An
exclusive filesystem lock remains owned until the worker exits its critical
section; an unreaped worker prevents overlapping filesystem mutations. Private,
checksummed journals bind the command, approved hash, original pathname and file
identities. A completed journal can reconcile the database after a lost worker
reply or agent restart. A previously issued execution receipt is preserved;
later filesystem completion enters separate durable recovery evidence. An unresolved
native mutation pauses quarantine/restore dispatch across backend changes while
inventory and reporting remain available.

Quarantine verifies a fresh broker hash and moves the selected directory entry
without replacing existing evidence. It then verifies and syncs an independent
private copy before committing success. An old writable descriptor or hard link
cannot change that retained copy. A replacement racing the capture cannot produce
success with different bytes: captured mismatches remain private for review.
Existing hard links and already-open handles elsewhere are not revoked.

Restore verifies a private copy and publishes it atomically without overwriting an
existing destination. New restore intents use retained-byte verification and can
run after the live response broker is removed. Original broker intents preserve
their serialized digest and binding requirements for recovery. The published file
starts with private `0600` permissions;
original ownership, ACLs and executable permissions are not restored. Files and
directory entries are synced before a completion record. Recovery may finish
private evidence retention or reconcile an already-published restore, but it does
not repeat an external source move or publish an uncompleted restore. Changed
parents, corrupted journals and conflicting identities require review. Both
operations currently require the same filesystem as endpoint quarantine storage.
The mutation store admits at most 2,048 operation records and 1 GiB of file data,
with 16 MiB of free disk headroom reserved. Archiving records and resolving retained
conflicts currently require local operator review.

These mutation workers serve all Linux/macOS quarantine and restore paths,
including portable responses without a native scanner. Portable source reads bind
the exact identity and approved hash inside the worker; a persistent native broker
binding prevents direct-read fallback even after the broker stops. Completed
legacy quarantine records are restorable without an original operation journal;
incomplete legacy records still require local review. Linux protected source reads use a
separate child under the locally configured excluded scanner UID/GID, pinned in the
intent, with read/search capability only. The child binds the exact file identity
before and after hashing. It inherits the mutation lock's open file description;
the supervisor closes without unlocking after handoff. Thus a reader that has not
exited continues excluding recovery even after its supervisor exits. Descriptor
lifetime and unrelated-exec exclusion are tested; an actual uninterruptible kernel
filesystem stall is not simulated.

The portable Windows mutation path still requires conversion. Agent state I/O and worker
loading still assume trusted local storage. Native Mac tests with prevention
actively blocking the source file, signing and power-loss validation remain
required; the automated interruption tests simulate application crashes at
filesystem transaction boundaries.

## Verified build component in portal installers

On a Mac, after both command-line executables have been signed and accepted by
Gatekeeper, provision the catalog with the adapter:

```sh
python3 tools/package_endpoint.py \
  --binary target/release/athernex-endpoint \
  --target macos-aarch64 \
  --native-adapter target/release/athernex-endpoint-native \
  --require-native-signature
```

Use `macos-x86_64` for Intel. Packaging checks the native architecture, a combined
64 MiB executable budget, both signatures and Gatekeeper acceptance, and the
adapter's boolean Endpoint Security entitlement. Debug-enabled adapters are
rejected. Signature checks operate on private snapshots, and only those bytes are
published. The management executable must answer the installer metadata command
with the component's expected hash. The release manifest records the optional
component; the portal verifies its hash and architecture before adding it to the
bundle. Development catalogs without a native component continue to work.

The Mac installer checks the declared hash, signatures, Gatekeeper acceptance and
entitlement before stopping an existing service. It stages verified adapter bytes
privately and replaces `/Library/AthernexEndpoint/athernex-endpoint-native` only
when the copy is complete. After enrollment and signature provisioning, it invokes
`configure-native-protection STATE_DIR SIGNED_ADAPTER` to prepare the scanner and
local policy. The restarted controller starts enabled native services. Live
allow/deny probes, native installation/recovery testing and privacy authorization
remain release gates; installation does not establish verified prevention.

Setup creates a hidden, disabled `_athernexav` account and dedicated group using
the [ClamAV service-account procedure](https://docs.clamav.net/manual/Installing/Add-clamav-user.html).
It selects unused numeric IDs in 200–499 from the configured directory search
policy and journals generated record IDs before mutation. The authentication
authority uses Apple's [disabled-user value](https://github.com/apple-oss-distributions/DirectoryService/blob/main/APIFramework/DirServicesConst.h).
It does not set a login password or add group memberships. Repeated setup verifies
the recorded identities, disabled authentication, shell, home, primary group and
absence of supplementary groups. Foreign records, changed completed accounts,
shared numeric IDs and unrelated engine directories are rejected. Interrupted
account creation can resume only for the original generated record identities.
An account creation interrupted before its first generated ID is stored requires
local review. A machine-wide setup lock serializes this application's account
creation across endpoint state directories.

The scanner database is copied to `/Library/AthernexEndpointAV/db`, outside the
private management state. The scanner owns only its `0700` runtime directory;
root owns the engine directory and read-only-to-scanner signature files. Setup
holds controller, management and protection locks, refuses outstanding service
groups, rejects linked or untrusted signature inputs, and limits bootstrap to 128 files and
1 GiB. It commits the protection and signature-maintenance configuration only
after preparation succeeds. Existing local policy is preserved, including a
disabled policy. Select antivirus provisioning in the portal or prepare signatures
before invoking native setup. An incomplete, unowned engine directory is not
adopted automatically. Directory Service and Apple privacy behavior still require
validation on an authorized Mac.

These checks use Apple's [entitlement inspection guidance](https://developer.apple.com/documentation/security/resolving-common-notarization-issues)
and [Developer ID distribution requirements](https://developer.apple.com/developer-id/).
Local packaging tests supply controlled signature replies. Installer ordering
tests run in a temporary filesystem tree with controlled Apple-tool replies; they
do not execute codesign, Gatekeeper, launchd or Endpoint Security on a Mac.

## Owned scanner and adapter supervision

The development command `athernex-endpoint-native supervise PRIVATE_SERVICE_PLAN.json`
runs ClamAV and the authorization adapter together on macOS. It requires root,
the signing/privacy authorization below, an existing dedicated scanner account,
and a prepared signature database. The endpoint's `protect STATE_DIR` command
prepares this plan from local configuration and starts the native supervisor as an
owned child. The controller starts `protect` independently from management when
protection is enabled. The installer now prepares the dedicated account, runtime
and configuration when the signed native component is included and signatures are
available; this setup has not yet been executed on a Mac.

For a custom deployment, prepare those resources on a signed, authorized test Mac
and merge a `protection` section into the existing private endpoint `config.json`.
For example:

```json
{
  "protection": {
    "enabled": true,
    "roots": ["/private/var/athernex-native-test/watched"],
    "daemon": "/usr/local/clamav/sbin/clamd",
    "monitor": "/Library/AthernexEndpoint/athernex-endpoint-native",
    "database": "/private/var/athernex-native-engine/db",
    "runtime": "/private/var/athernex-native-engine/runtime",
    "engine_uid": 1234,
    "engine_gid": 1234
  }
}
```

Use the actual dedicated account's UID/GID and canonical installed paths. Keep
signature maintenance pointed at the same database. The adapter and scanner must
be outside watched roots; the complete endpoint state directory is also excluded.
On controller restart, management and native protection run in separate owned
process groups. A management crash preserves protection. A protection-process
failure is retried after five seconds, subject to existing group/engine ownership
checks. Controller death triggers cleanup through each worker's parent watcher.
The controller retains bounded child output for exit diagnostics.
This lifecycle fixture covers the managed service tree. Bounded shell automation
and external maintenance commands now have a separate process watcher, registered
before the executable starts. On Mac it watches both the owner and command leader
with `kqueue`; inherited descriptors are enumerated and closed through the
[`proc_pidinfo` syscall wrapper](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c).
It retains no agent database lock or command output pipe. Actual endpoint-process
tests on Linux verify background-child cleanup, agent death during an approved
script, an interrupted receipt after restart and no script replay. Mac execution
is still unverified. Deliberate session/group escapes and privilege changes are
outside this process-group lifetime mechanism; it is not a script sandbox.

Enabled macOS protection always routes scans and quarantine through the private
native broker, including before the broker has established its first binding.
Startup failure cannot cause a direct-read fallback. Manual update admission
holds native state and engine locks and refuses remaining service groups; changing
`enabled` to false does not bypass a previously prepared native service plan.
macOS automatic agent replacement remains gated on native validation.

`protection-status` reports the backend and configured scope. Status must match the
plan and boot, be fresh, and have a live supervisor lease and process groups. It
reports `starting`, `degraded` or `active`; `--require-active` succeeds only with
fresh complete blocking proof and live owned services. The controller connection
does not promote process liveness to verified prevention.

For a controlled Mac test, prepare canonical, root-owned directories outside the
watched roots. Keep the native state and plan private (`0700` and `0600`). The
database and scanner runtime must be siblings under a dedicated root-owned
directory; the runtime must be `0700` and owned by the dedicated scanner UID/GID.
The daemon must be a canonical, root-owned regular executable. Replace the paths
and illustrative IDs with the installed engine and scanner identity:

```json
{
  "schema": 1,
  "policy": {
    "roots": ["/private/var/athernex-native-test/watched"],
    "socket": "/private/var/athernex-native-engine/runtime/clamd.sock",
    "state": "/private/var/athernex-native-state",
    "scanner_uid": 1234,
    "scan_timeout_ms": 1000
  },
  "daemon": "/usr/local/clamav/sbin/clamd",
  "database": "/private/var/athernex-native-engine/db",
  "scanner_gid": 1234,
  "startup_secs": 120
}
```

The supervisor binds the engine directory to that endpoint state and scanner
identity. Separate live locks reject duplicate startup. Each worker checks its
actual parent, the plan digest, supervisor status and both live ownership locks.
The scanner wrapper drops supplementary groups and changes to the dedicated
UID/GID before starting ClamAV. Generated configuration uses a private socket,
bounded scan sizes and queue, and foreground operation. Scanner health requests
have short socket deadlines. Child output is drained with bounded work and a
bounded retained tail; diagnostic output cannot grow without limit.

A scanner or adapter failure stops the pair. Private checksummed journals record
each owned process group before the scanner can spawn. Restart refuses while any
previous group still exists in the same boot session. It never signals a process
group recovered from disk, because its identifier might have been reused. A
remaining group, damaged journal or attempted engine/state rebinding requires
local review. Root-trusted local storage remains a requirement.

macOS workers use a parent-exit watcher to terminate their owned group if the
supervisor dies. The boot identity comes from Apple's
[`kern.bootsessionuuid`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c).
This lifecycle code cross-compiles for Intel and Apple silicon; its native Mac
behavior still needs validation. Linux fixtures exercise the corresponding
process ownership and real ClamAV transport without invoking Endpoint Security.

`service-status.json` reports `starting`, `running-unverified`, `running-verified`
or `failed`. Only a valid complete proof permits `runtime_protection_verified`
to become true. The Linux lifecycle fixture always remains unverified. Native
execution of the automatic health path, controller recovery and signed Mac
installation still require validation on both supported Mac architectures.

To reproduce the isolated lifecycle fixture after preparing the engine and Docker
image described in [endpoint verification](endpoint-fleet.md#verification-and-remaining-release-gates):

```sh
cargo build --locked --release -p athernex-endpoint-native -p athernex-endpoint
python3 tools/verify_native_service.py --engine-prefix /tmp/athernex-native-av/engine/usr/local
```

The real-engine checks cover dedicated scanner identity, exact-byte verdicts,
persisted group ownership, duplicate startup, unowned-worker rejection, engine
rebinding refusal, scanner/adapter crashes, supervisor death and clean restart,
plus controller startup, independent management recovery, protection-process
recovery, controller death/restart and update exclusion even after policy disable.
They also cover automatic filesystem setup, private scanner runtime ownership,
independent signatures, linked/writable signature rejection, foreign ownership,
live-service exclusion and preservation of an intentionally disabled policy.
The container uses disposable files and a network-disabled runtime. These checks
use an explicit Linux fixture dispatch for the native protection process; the
controller, wrapper, scanner and broker are real. They do not install a host service
or validate macOS authorization. Full endpoint cross-compilation from Linux is
currently limited by `libproc`'s host-specific generated bindings; native Mac CI
is still required. The standalone adapter passes both Mac cross-target checks.

## Automatic blocking health

Before starting the scanner and adapter, the supervisor prepares a private sample
directory in each configured root. Writes use directory descriptors and refuse
symlinks, shared hard links and foreign ownership. Each directory contains clean
and synthetic text plus clean and synthetic executable images. The harmless
executable template comes from the trusted system `true` utility; on Mac, a
temporary copy in private native state receives a unique local ad-hoc signature.
Only its unique bytes and the synthetic text enter `athernex-health.hsb` in the
dedicated scanner database. Installed system binaries are unchanged.

All six operations per root must succeed before protection activates. This
prevents permissions, `noexec` mounts, signing policy or another antivirus from
being mistaken for this adapter's blocking. Environments that disallow the
ad-hoc probe executable will fail this baseline and require an appropriate signed
probe packaging strategy before deployment.

After activation, a separate health thread tests clean and detected open, execute
and memory-map operations for every root. Memory mapping uses read-only
descriptors opened before activation. Each denied operation needs its exact
delivered native receipt, including actor PID/version, operation, original file
identity, hash and detection. A complete cycle has a 15-second budget; successful
cycles repeat after 30 seconds, and failures retry after five seconds. No partial
cycle can establish health. A filesystem stall can retain the worker and service
leases; a stalled cycle cannot refresh its proof. Filesystem operations still
depend on the operating system and do not have an interruptibility guarantee.

Proofs bind the current plan, manifest, boot, supervisor and adapter. They expire
after 45 seconds and are published under immutable hashes, so readers can finish
validating the previous status while the next proof is written. The private proof
directory has a 64-entry admission limit; proofs older than 75 seconds and
validated interrupted temporary writes are reclaimed. Root/sample replacement,
stale native status, failed delivery, event gaps or dropped evidence invalidate
health. The raw adapter subscription status continues to report unverified;
only the supervisor combines it with live blocking proof.

Known synthetic denials go to a separate 512-record diagnostic journal, using
the exact policy, owner, path, file identity, hash and detection. Other detections
retain the existing durable malware inbox. Approved scans also recognize exact
owned health samples and count them separately; matching bytes at a different
path remain detections. A filename prefix or signature name alone never excludes
evidence. Thus routine health checks cannot feed their own malware automation.

The Rust proof-validation tests use controlled receipts. Linux tests exercise
real sample execution/mapping, actual ClamAV signatures and approved scans, but
do not exercise Apple's authorization API. The native gate below must pass on a
properly signed, authorized Mac before this path can be treated as validated.

## Native build and controlled validation

Build on a Mac with the Rust toolchain and Xcode Command Line Tools:

```sh
cargo test --locked -p athernex-endpoint-native
cargo build --locked --release -p athernex-endpoint-native
```

Before running authorization, the executable needs Apple's approved Endpoint
Security entitlement and an appropriate signing/provisioning identity. Root and
Full Disk Access are also required. The entitlement template is
`infrastructure/endpoint/macos/endpoint-security.entitlements.plist`; copying it
does not grant authorization. Use the team's approved signing and deployment
process. This repository does not disable SIP, install untrusted certificates or
automatically change privacy permissions. See
[Apple's Endpoint Security deployment information](https://developer.apple.com/system-extensions/).

Prepare a private root-owned policy file and existing state directory, plus a
ClamAV daemon under a dedicated non-root UID. Its socket must be owned by root or
that UID and inaccessible to other users. Use canonical paths: `/var` and `/tmp`
are symlinks on macOS, so use their canonical `/private/...` paths instead. For
example, replacing the illustrative UID with the actual dedicated scanner UID:

```json
{
  "roots": ["/private/var/athernex-native-test/watched"],
  "socket": "/private/var/athernex-native-runtime/clamd.sock",
  "state": "/private/var/athernex-native-state",
  "scanner_uid": 1234,
  "scan_timeout_ms": 1000
}
```

State, scanner socket, signature files and daemon logs must remain outside the
watched tree. Limit initial validation to disposable test files. After approved
signing and privacy authorization, invoke:

```sh
sudo /ABSOLUTE/PATH/athernex-endpoint-native run /PRIVATE/ROOT_OWNED/policy.json
```

Validate clean and signature-matched open/exec/mmap operations, private files,
deadline saturation, daemon death, adapter/controller death, root replacement and
recovery on both Intel and Apple silicon. Installer configuration is implemented;
native execution and blocking health validation remain unfinished, so
do not use it as validated replacement protection.

`tools/verify_macos_native.py` provides the controlled native authorization and
response gate. Run it on an authorized Mac with signed, Gatekeeper-accepted agent
and adapter binaries, an installed ClamAV engine and the existing dedicated
scanner account prepared by the installer:

```sh
sudo python3 tools/verify_macos_native.py \
  --adapter /ABSOLUTE/PATH/athernex-endpoint-native \
  --agent /ABSOLUTE/PATH/athernex-endpoint \
  --engine-prefix /usr/local/clamav \
  --report /PRIVATE/ROOT_OWNED/native-macos-runtime.json
```

The gate creates temporary watched files and a private synthetic signature
database. It locally ad-hoc signs a temporary copy of `/usr/bin/true` with a
unique identifier before computing its whole-file signature; the installed
utility and shipped binaries are not modified. Clean and synthetic files must
both work before protection starts. After startup, clean operations must succeed
and synthetic open, execute and memory-map operations must be denied. Mapping
uses descriptors opened before activation, so an open denial cannot substitute
for a mapping denial. Each denial must have a fresh delivered native receipt
matching the requesting process, operation, file identity, hash and detection.
A permissions error or scanner failure alone cannot pass the gate.

The same run requires quarantine, committed-action recovery, restore with renewed
blocking, and removal of authorization after owned service shutdown. It installs
no account or launchd job, retains its temporary files if worker cleanup cannot
be confirmed, and writes a report only after all checks pass. **This gate has not
been run on a Mac.** It now requires the supervisor's automatic blocking health
to become verified and verifies approved scans of active health samples. Passing
this controlled gate would not establish production readiness. Native signing,
notarization, deployment, installer setup, controller validation and load/failure
tests remain release requirements. Live proof establishes current enforcement
for the configured probes and roots; it does not establish complete detection
coverage or tamper resistance.

## Reproducible scanner checks on Linux

The cross-platform transport tests use controlled sockets to exercise mutation,
replacement, deadlines and invalid responses. A separate fixture uses real ClamAV
with a tiny benign custom signature database inside a network-isolated container:

```sh
cargo build --locked --release -p athernex-endpoint-native -p athernex-endpoint
python3 tools/prepare_native_protection_fixture.py --output /tmp/athernex-native-av
docker build -t athernex-native-protection-fixture:local infrastructure/endpoint/tests
python3 tools/verify_native_adapter.py --engine-prefix /tmp/athernex-native-av/engine/usr/local
```

The container has a read-only root filesystem, no network and only private fixture
data. It adds `SETUID` to test rejection of a client under another UID even when
the fixture temporarily permits socket access, and `SYS_ADMIN` for a fanotify
permission barrier limited to the temporary watched directory.
It verifies exact-byte clean/detected verdicts, scope rejection, queue saturation
and recovery, crash/stale-socket recovery, and refusal of symlinks, FIFOs, oversized
files and an unavailable scanner. The barrier denies ordinary opens, including
root, while permitting the registered broker process to read. Quarantine,
restore and committed recovery must still succeed; a dead broker must refuse
the mutation. A preopened descriptor remains mappable, demonstrating that this
open barrier cannot establish memory-map prevention. All 22 checks passed with
real ClamAV. This proves the Unix scan/response transport and shared mutation
behavior under an actual kernel read barrier; it does not execute Apple's
authorization API or implement a malware decision engine. The native
CI matrix builds and tests the adapter on Mac runners but does not have signing or
Endpoint Security permissions provisioned.
