import Foundation
import CryptoKit

// This is the actual provider queue/state implementation, also exercised by the
// host controls. It never retains NEFilterFlow or packet objects.
final class HandoffLosses {
    private let counter: OpaquePointer
    init() throws { guard let p = AXCountersCreate() else { throw SourceError.refused }; counter = p }
    deinit { AXCountersDestroy(counter) }
    func drop() { _ = AXCountersIncrement(counter, 0) }
    var value: UInt64 { AXCountersRead(counter, 0) }
    var overflowed: Bool { AXCountersOverflowed(counter) }
}
final class SourceHolder {
    let losses: HandoffLosses
    private let lock = NSLock()
    private var current: SourceState?
    init() throws { losses = try HandoffLosses() }
    func snapshot() -> SourceState? {
        guard lock.try() else { losses.drop(); return nil }
        defer { lock.unlock() }; return current
    }
    func replace(_ value: SourceState?) -> SourceState? {
        lock.lock(); defer { lock.unlock() }; let old = current; current = value; return old
    }
    func contains(_ value: SourceState) -> Bool {
        lock.lock(); defer { lock.unlock() }; return current === value
    }
    #if AX_TESTS
    func withLookupHeld(_ body: () throws -> Void) rethrows {
        lock.lock(); defer { lock.unlock() }; try body()
    }
    #endif
}
final class SourceState {
    struct Record { let receipt: UInt64; let bytes: Data }
    struct Batch { let id: UInt64; let count: Int; let bytes: Data; let digest: String }
    let stream: String
    let started: UInt64
    private let counters: OpaquePointer
    private let handoff: HandoffLosses
    private let handoffStart: UInt64
    private var handoffEnd: UInt64?
    private let lock = NSLock()
    private var records: [Record] = []
    private var retainedBytes = 0
    private var receipt: UInt64 = 0
    private var acknowledged: UInt64 = 0
    private var acknowledgedDigest = ""
    private var inflight: Batch?
    private var running = false
    private var stopping = false
    private var configurationFailed = false
    private var overflowed = false

    init(handoff: HandoffLosses? = nil) throws {
        let losses = try handoff ?? HandoffLosses()
        self.handoff = losses; handoffStart = losses.value
        guard let c = AXCountersCreate() else { throw SourceError.refused }
        do { stream = hex(try randomBytes()); started = milliseconds(); guard started > 0 else { throw SourceError.refused } }
        catch { AXCountersDestroy(c); throw SourceError.refused }
        counters = c
    }
    deinit { AXCountersDestroy(counters) }
    func activated(_ good: Bool) {
        lock.lock(); defer { lock.unlock() }
        running = good; configurationFailed = !good
    }
    func stop() {
        lock.lock(); stopping = true; running = false; handoffEnd = handoff.value
        // OS stop is an explicit unknown interval, not a successful delivery.
        // Clear owned commit before permitting a fresh source on this instance;
        // old callback/session references may outlive stop but retain no queue.
        records.removeAll(keepingCapacity: false); retainedBytes = 0; inflight = nil
        lock.unlock()
    }
    // Kept separate so the actual-state controls can pause between reception and
    // try-lock. No receipt number is assigned before queue serialization.
    func received() -> Bool { AXCountersIncrement(counters, 0) }
    func admit(_ make: (String, UInt64) throws -> Data?) {
        guard lock.try() else { _ = AXCountersIncrement(counters, 3); return }
        defer { lock.unlock() }
        guard running, !stopping, !overflowed, receipt < UInt64.max else {
            if receipt == UInt64.max { overflowed = true }
            _ = AXCountersIncrement(counters, 3); return
        }
        receipt += 1
        do {
            guard let bytes = try make(stream, receipt) else { _ = AXCountersIncrement(counters, 1); return }
            guard !bytes.isEmpty, bytes.count <= originalByteLimit else { throw SourceError.refused }
            guard records.count < queueRecordLimit, bytes.count <= queueByteLimit - retainedBytes else {
                _ = AXCountersIncrement(counters, 4); return
            }
            records.append(Record(receipt: receipt, bytes: bytes)); retainedBytes += bytes.count
        } catch { _ = AXCountersIncrement(counters, 2) }
    }
    func transportFailed() { _ = AXCountersIncrement(counters, 5) }
    private func health() -> [String: Any] {
        let excluded = AXCountersRead(counters, 1)
        let rejected = AXCountersRead(counters, 2), ownCallback = AXCountersRead(counters, 3)
        let dropped = AXCountersRead(counters, 4), transport = AXCountersRead(counters, 5)
        // Contending callbacks can count drops without taking this lock. Read
        // their terminal categories first and the seq-cst received upper bound
        // last, so a newly counted drop cannot outrun its received snapshot.
        let ownReceived = AXCountersRead(counters, 0)
        let end = handoffEnd ?? handoff.value
        let missed = end >= handoffStart ? end - handoffStart : 0
        let r = ownReceived.addingReportingOverflow(missed), c = ownCallback.addingReportingOverflow(missed)
        let received = r.overflow ? UInt64.max : r.partialValue
        let callback = c.overflow ? UInt64.max : c.partialValue
        let over = overflowed || AXCountersOverflowed(counters) || handoff.overflowed || r.overflow || c.overflow
        let error: String
        if over { error = "Network source counters overflowed" }
        else if configurationFailed { error = "Network source configuration failed" }
        else if stopping { error = "Network source is stopping" }
        else if rejected > 0 { error = "Network source projection was rejected" }
        else if callback > 0 { error = "Network source callback lost records" }
        else if dropped > 0 { error = "Network source queue lost records" }
        else if transport > 0 { error = "Network source transport failed" }
        else { error = "" }
        let pressure = records.count == queueRecordLimit || retainedBytes == queueByteLimit
        let state = stopping ? "stopped" : (!running ? "starting" : (error.isEmpty ? "active" : "degraded"))
        return ["stream_id": stream, "state": state, "source_policy_sha256": sourcePolicy,
            "started_ms": started, "checked_ms": milliseconds(), "received_records": received,
            "admitted_records": UInt64(0), "excluded_records": excluded, "rejected_records": rejected,
            "callback_drops": callback, "queue_drops": dropped, "transport_errors": transport,
            "pending_records": records.count, "pending_bytes": retainedBytes,
            "restarts": UInt64(0), "loss_signals": UInt64(0), "kernel_loss_observability": "unavailable",
            "backpressured": pressure, "error": error]
    }
    func response(epoch: UInt64, request: UInt64, nonce: Data, pull: Bool = false,
                  ack: (UInt64, String)? = nil) throws -> (Data, Data) {
        lock.lock(); defer { lock.unlock() }
        if let (id, digest) = ack {
            if id == acknowledged && id != 0 && digest == acknowledgedDigest { /* idempotent */ }
            else {
                guard let b = inflight, b.id == id, b.digest == digest,
                      b.count <= records.count else { throw SourceError.refused }
                for record in records.prefix(b.count) { retainedBytes -= record.bytes.count }
                records.removeFirst(b.count); acknowledged = id; acknowledgedDigest = digest; inflight = nil
            }
        }
        if pull && inflight == nil && !records.isEmpty {
            guard acknowledged < UInt64.max else { overflowed = true; throw SourceError.refused }
            var body = Data([0x5b]); var count = 0
            for record in records.prefix(64) {
                let extra = record.bytes.count + (count == 0 ? 0 : 1) + 1
                if extra > frameLimit - controlLimit - body.count { break }
                if count != 0 { body.append(0x2c) }
                body.append(record.bytes); count += 1
            }
            guard count > 0 else { throw SourceError.refused }; body.append(0x5d)
            inflight = Batch(id: acknowledged + 1, count: count, bytes: body, digest: hex(Data(SHA256.hash(data: body))))
        }
        let b = pull ? inflight : nil
        let batchID: UInt64 = b?.id ?? 0
        let batchDigest: String = b?.digest ?? ""
        let recordCount: Int = b?.count ?? 0
        let control = try json(["version": 1, "nonce": hex(nonce), "epoch": epoch, "request_id": request,
            "status": ["health": health(), "last_acked_batch_id": acknowledged],
            "batch_id": batchID, "batch_sha256": batchDigest, "record_count": recordCount])
        let body = b?.bytes ?? Data()
        guard control.count <= controlLimit, body.count <= frameLimit - control.count else { throw SourceError.refused }
        return (control, body)
    }
}
