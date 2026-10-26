import Foundation
import NetworkExtension

func require(_ condition: @autoclosure () throws -> Bool) throws { if try !condition() { throw SourceError.refused } }
func refused(_ body: () throws -> Void) throws {
    do { try body() } catch { return }
    throw SourceError.refused
}
func record(_ stream: String, _ receipt: UInt64) throws -> Data {
    try selectedProjection(stream: stream, receipt: receipt, flowID: "00000000-0000-0000-0000-000000000001",
        direction: 0, family: AF_INET, type: SOCK_STREAM, proto: 0, local: NSNull(), remote: NSNull(),
        application: NSNull(), process: NSNull(), time: (1, 0))
}
func control(_ r: (Data, Data)) throws -> [String: Any] {
    guard let c = try JSONSerialization.jsonObject(with: r.0) as? [String: Any] else { throw SourceError.refused }; return c
}
func health(_ r: (Data, Data)) throws -> [String: Any] {
    guard let c = try control(r)["status"] as? [String: Any], let h = c["health"] as? [String: Any] else { throw SourceError.refused }; return h
}
func u(_ d: [String: Any], _ name: String) -> UInt64? { (d[name] as? NSNumber)?.uint64Value }
let nonce = Data(repeating: 7, count: 32)

func projectionControls() throws {
    for family in [AF_INET, AF_INET6] {
        let address = family == AF_INET ? "127.0.0.1" : "::1"
        let endpoint = try numericEndpoint(host: address, port: "65535", family: family)
        for (proto, type) in [(Int32(0), SOCK_STREAM), (Int32(0), SOCK_DGRAM), (IPPROTO_TCP, SOCK_STREAM), (IPPROTO_UDP, SOCK_DGRAM)] {
            for direction in 0...2 {
                let data = try selectedProjection(stream: String(repeating: "a", count: 64), receipt: 1,
                    flowID: "00000000-0000-0000-0000-000000000001", direction: Int32(direction), family: family,
                    type: type, proto: proto, local: NSNull(), remote: endpoint,
                    application: token(nil), process: token(Data(repeating: 9, count: 32)), time: (1, 999_999_999))
                guard let d = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw SourceError.refused }
                try require((d["local"] as? NSNull) != nil); try require((d["source_app_audit_token_hex"] as? NSNull) != nil)
                try require((d["socket_protocol"] as? NSNumber)?.int32Value == proto)
            }
        }
    }
    let scoped = try numericEndpoint(host: "fe80::1%0", port: "0", family: AF_INET6)
    try require(u(scoped, "scope_id") == 0)
    for h in ["127.0.0.1\0.example", "example.test", "::1%en0", "::1%", "::1%1%2", String(repeating: "1", count: 81)] {
        try refused { _ = try numericEndpoint(host: h, port: "80", family: h.contains(":") ? AF_INET6 : AF_INET) }
    }
    for p in ["", "http", "65536", "-1", "1\0"] { try refused { _ = try numericEndpoint(host: "127.0.0.1", port: p, family: AF_INET) } }
    try refused { _ = try token(Data(repeating: 0, count: 31)) }
    try refused { _ = try selectedProjection(stream: String(repeating: "a", count: 64), receipt: 1,
        flowID: "00000000-0000-0000-0000-000000000001", direction: 0, family: AF_INET, type: SOCK_DGRAM,
        proto: IPPROTO_TCP, local: NSNull(), remote: NSNull(), application: NSNull(), process: NSNull(), time: (1, 0)) }
}
func queueControls() throws {
    let s = try SourceState(); s.activated(true)
    for _ in 0..<queueRecordLimit { try require(s.received()); s.admit(record) }
    try require(s.received()); s.admit(record)
    let r = try s.response(epoch: 1, request: 1, nonce: nonce, pull: true)
    let h = try health(r), c = try control(r)
    try require(u(h, "pending_records") == UInt64(queueRecordLimit)); try require(u(h, "queue_drops") == 1)
    try require(u(c, "record_count") == 64); try require(r.0.count + r.1.count <= frameLimit)
    let repeated = try s.response(epoch: 2, request: 1, nonce: Data(repeating: 8, count: 32), pull: true)
    try require(repeated.1 == r.1)
    guard let digest = c["batch_sha256"] as? String else { throw SourceError.refused }
    try refused { _ = try s.response(epoch: 2, request: 2, nonce: nonce, ack: (1, String(repeating: "0", count: 64))) }
    let ack = try s.response(epoch: 2, request: 2, nonce: nonce, ack: (1, digest))
    try require(u(try health(ack), "pending_records") == UInt64(queueRecordLimit - 64))
    _ = try s.response(epoch: 2, request: 3, nonce: nonce, ack: (1, digest))
    let bytes = try SourceState(); bytes.activated(true)
    let full = queueByteLimit / originalByteLimit, remainder = queueByteLimit % originalByteLimit
    for length in Array(repeating: originalByteLimit, count: full) + [remainder] {
        try require(bytes.received()); bytes.admit { stream, receipt in
            var data = try record(stream, receipt); guard data.count <= length else { throw SourceError.refused }
            data.append(Data(repeating: 32, count: length - data.count)); return data
        }
    }
    try require(bytes.received()); bytes.admit(record)
    let exact = try health(bytes.response(epoch: 1, request: 1, nonce: nonce))
    try require(u(exact, "pending_bytes") == UInt64(queueByteLimit)); try require(u(exact, "queue_drops") == 1)
}
func orderingAndStopControls() throws {
    let s = try SourceState(); s.activated(true)
    // Callback A actually pauses before try-lock; independently tagged B enters
    // first. The control runs the production received/admit functions.
    let firstReceived = DispatchSemaphore(value: 0), resumeFirst = DispatchSemaphore(value: 0), firstDone = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        if s.received() {
            firstReceived.signal()
            if resumeFirst.wait(timeout: .now() + 3) == .success {
                s.admit { stream, receipt in
                    var d = try JSONSerialization.jsonObject(with: record(stream, receipt)) as? [String: Any]
                    d?["flow_id"] = "00000000-0000-0000-0000-00000000000a"
                    guard let d else { throw SourceError.refused }; return try json(d)
                }
            }
        }
        firstDone.signal()
    }
    try require(firstReceived.wait(timeout: .now() + 3) == .success)
    try require(s.received()); s.admit { stream, receipt in
        var d = try JSONSerialization.jsonObject(with: record(stream, receipt)) as? [String: Any]
        d?["flow_id"] = "00000000-0000-0000-0000-00000000000b"
        guard let d else { throw SourceError.refused }; return try json(d)
    }
    resumeFirst.signal(); try require(firstDone.wait(timeout: .now() + 3) == .success)
    let r = try s.response(epoch: 1, request: 1, nonce: nonce, pull: true)
    guard let originals = try JSONSerialization.jsonObject(with: r.1) as? [[String: Any]] else { throw SourceError.refused }
    try require(originals.count == 2); try require(u(originals[0], "receipt_sequence") == 1); try require(u(originals[1], "receipt_sequence") == 2)
    try require(originals[0]["flow_id"] as? String == "00000000-0000-0000-0000-00000000000b")
    try require(originals[1]["flow_id"] as? String == "00000000-0000-0000-0000-00000000000a")
    let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        if s.received() { s.admit { stream, receipt in held.signal(); guard release.wait(timeout: .now() + 3) == .success else { throw SourceError.refused }; return try record(stream, receipt) } }
        finished.signal()
    }
    try require(held.wait(timeout: .now() + 3) == .success)
    try require(s.received()); s.admit(record); release.signal()
    try require(finished.wait(timeout: .now() + 3) == .success)
    let h = try health(s.response(epoch: 1, request: 2, nonce: nonce))
    try require(u(h, "received_records") == 4); try require(u(h, "callback_drops") == 1)
    let holder = try SourceHolder(), first = try SourceState(handoff: holder.losses)
    first.activated(true); _ = holder.replace(first)
    holder.withLookupHeld { _ = holder.snapshot() }
    let handoff = try health(first.response(epoch: 1, request: 1, nonce: nonce))
    try require(u(handoff, "received_records") == 1); try require(u(handoff, "callback_drops") == 1)
    try require(first.received()); first.admit(record); _ = holder.replace(nil); first.stop()
    let second = try SourceState(handoff: holder.losses); second.activated(true); _ = holder.replace(second)
    try require(first.stream != second.stream)
    let stopped = try health(first.response(epoch: 1, request: 2, nonce: nonce))
    try require(u(stopped, "pending_records") == 0); try require(stopped["state"] as? String == "stopped")
    try require(u(try health(second.response(epoch: 2, request: 1, nonce: nonce)), "callback_drops") == 0)
}
func sessionControls() throws {
    let s = try SourceState(); s.activated(true); try require(s.received()); s.admit(record)
    let session = ProviderSession(epoch: 3, state: s, scope: { true })
    var pair: (Data, Data)?
    let policy = Data(stride(from: 0, to: sourcePolicy.count, by: 2).compactMap { i -> UInt8? in
        let a = sourcePolicy.index(sourcePolicy.startIndex, offsetBy: i), b = sourcePolicy.index(a, offsetBy: 2)
        return UInt8(sourcePolicy[a..<b], radix: 16)
    })
    session.hello(1, nonce: nonce, policy: policy) { pair = ($0, $1) }
    guard let hello = pair else { throw SourceError.refused }; try require(!hello.0.isEmpty)
    session.pull(2, request: 1, nonce: nonce) { pair = ($0, $1) }; try require(pair?.0.isEmpty == true)
    session.pull(3, request: 1, nonce: nonce) { pair = ($0, $1) }; try require(pair?.1.isEmpty == false)
    session.detach(3, request: 2, nonce: nonce) { pair = ($0, $1) }; try require(pair?.0.isEmpty == false)
    session.pull(3, request: 3, nonce: nonce) { pair = ($0, $1) }; try require(pair?.0.isEmpty == true)
    try require(u(try health(s.response(epoch: 4, request: 1, nonce: nonce)), "pending_records") == 1)
    try require(!exactVersion(true)); try require(!exactVersion(1.0)); try require(exactVersion(1))
}
final class PausedScope {
    private let lock = NSLock()
    private var calls = 0
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    func check() -> Bool {
        lock.lock(); calls += 1; let count = calls; lock.unlock()
        if count == 3 { entered.signal(); return release.wait(timeout: .now() + 3) == .success }
        return true
    }
}
func retirementControl() throws {
    let s = try SourceState(); s.activated(true); try require(s.received()); s.admit(record)
    let scope = PausedScope(), retired = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
    let observed = try HandoffLosses()
    let session = ProviderSession(epoch: 1, state: s, scope: scope.check, release: { retired.signal() })
    let policy = Data(stride(from: 0, to: sourcePolicy.count, by: 2).compactMap { i -> UInt8? in
        let a = sourcePolicy.index(sourcePolicy.startIndex, offsetBy: i), b = sourcePolicy.index(a, offsetBy: 2)
        return UInt8(sourcePolicy[a..<b], radix: 16)
    })
    session.hello(1, nonce: nonce, policy: policy) { _, _ in }
    var batch: (Data, Data)?
    session.pull(1, request: 1, nonce: nonce) { batch = ($0, $1) }
    guard let batch, let digest = try control(batch)["batch_sha256"] as? String else { throw SourceError.refused }
    let hash = Data(stride(from: 0, to: digest.count, by: 2).compactMap { i -> UInt8? in
        let a = digest.index(digest.startIndex, offsetBy: i), b = digest.index(a, offsetBy: 2)
        return UInt8(digest[a..<b], radix: 16)
    })
    DispatchQueue.global().async {
        session.ack(1, request: 2, nonce: nonce, batch: 1, digest: hash) { c, _ in
            if !c.isEmpty { observed.drop() }
        }
        done.signal()
    }
    try require(scope.entered.wait(timeout: .now() + 3) == .success)
    session.invalidate()
    try require(retired.wait(timeout: .now()) == .timedOut)
    scope.release.signal(); try require(done.wait(timeout: .now() + 3) == .success)
    try require(retired.wait(timeout: .now() + 3) == .success)
    session.invalidate(); try require(retired.wait(timeout: .now()) == .timedOut)
    try require(observed.value == 0)
    let after = try control(s.response(epoch: 2, request: 0, nonce: nonce))
    guard let status = after["status"] as? [String: Any] else { throw SourceError.refused }
    try require(u(status, "last_acked_batch_id") == 1)
}
@main
struct Controls {
    static func main() {
        do { try projectionControls(); try queueControls(); try orderingAndStopControls(); try sessionControls(); try retirementControl()
            print("Network metadata controls passed; mocked callbacks and XPC sessions only")
        } catch { fputs("Network metadata controls failed\n", stderr); exit(1) }
    }
}
