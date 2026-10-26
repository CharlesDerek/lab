import Foundation

enum UpgradeFailure: Error { case refused }
func upgradeObject(_ raw: Any?, keys: Set<String>) throws -> [String: Any] {
    guard let d = raw as? [String: Any], Set(d.keys) == keys else { throw UpgradeFailure.refused }; return d
}
func upgradeUInt(_ raw: Any?) throws -> UInt64 {
    guard let n = raw as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
          ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: n.objCType)),
          n.stringValue.first != "-", let v = UInt64(n.stringValue) else { throw UpgradeFailure.refused }; return v
}
func upgradeHex(_ raw: Any?, count: Int) throws -> String {
    guard let s = raw as? String, s.utf8.count == count,
          s.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw UpgradeFailure.refused }; return s
}
func upgradeHashes(_ raw: Any?) throws -> [String] {
    guard let a = raw as? [String], (1...4).contains(a.count), a == a.sorted(), Set(a).count == a.count else { throw UpgradeFailure.refused }
    return try a.map { try upgradeHex($0, count: 40) }
}
func upgradeVersion(_ raw: Any?) throws -> [UInt32] {
    guard let s = raw as? String, s.utf8.count <= 64 else { throw UpgradeFailure.refused }
    let fields = s.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...3).contains(fields.count) else { throw UpgradeFailure.refused }
    var result = try fields.map { part -> UInt32 in
        guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }),
              (part.count == 1 || part.first != "0"), let value = UInt32(part) else { throw UpgradeFailure.refused }; return value
    }
    while result.count < 3 { result.append(0) }; return result
}
struct UpgradePin {
    let raw: [String: Any]
    let hashes: [String]
    let version: [UInt32]
    init(_ value: Any?) throws {
        raw = try upgradeObject(value, keys: ["executable_sha256", "cdhashes", "info_plist_sha256", "bundle_version", "short_version"])
        _ = try upgradeHex(raw["executable_sha256"], count: 64); _ = try upgradeHex(raw["info_plist_sha256"], count: 64)
        hashes = try upgradeHashes(raw["cdhashes"]); version = try upgradeVersion(raw["bundle_version"]); _ = try upgradeVersion(raw["short_version"])
    }
}
struct UpgradePlanValue {
    let raw: [String: Any]
    let identity: PeerIdentity
    let old: UpgradePin
    let new: UpgradePin
    let containerHashes: [String]
    let submit: Bool
    init(_ value: Any?, identity expected: PeerIdentity) throws {
        raw = try upgradeObject(value, keys: ["mode", "transaction_id", "generation", "identity", "source_policy_sha256", "old", "new", "container_cdhashes"])
        identity = try PeerIdentity(raw["identity"])
        guard identity == expected, raw["source_policy_sha256"] as? String == sourcePolicy,
              ["submit", "reconcile"].contains(raw["mode"] as? String ?? ""), try upgradeUInt(raw["generation"]) > 0 else { throw UpgradeFailure.refused }
        _ = try upgradeHex(raw["transaction_id"], count: 64)
        old = try UpgradePin(raw["old"]); new = try UpgradePin(raw["new"]); containerHashes = try upgradeHashes(raw["container_cdhashes"])
        guard old.version.lexicographicallyPrecedes(new.version), old.hashes != new.hashes else { throw UpgradeFailure.refused }
        submit = raw["mode"] as? String == "submit"
    }
}

// This guard is used by the actual SDK delegate. Clock injection is only into
// the guard: production always uses ContinuousClock, including sleep time.
final class UpgradeAttemptGuard {
    private let clock: () -> ContinuousClock.Instant
    private let deadline: ContinuousClock.Instant
    private(set) var submitted = false
    private(set) var replaced = false
    private(set) var replacementAllowed = false
    private(set) var live = true
    init(claimStarted: ContinuousClock.Instant, permitMilliseconds: UInt64,
         clock: @escaping () -> ContinuousClock.Instant = { ContinuousClock.now }) throws {
        guard (1...300_000).contains(permitMilliseconds) else { throw UpgradeFailure.refused }
        self.clock = clock; deadline = claimStarted.advanced(by: .milliseconds(Int64(permitMilliseconds)))
    }
    func submit() -> Bool { guard live, !submitted, clock() < deadline else { return false }; submitted = true; return true }
    func retire() { live = false }
    func replace(verify: () -> Bool) -> Bool {
        guard live, submitted, !replaced, clock() < deadline else { return false }
        // Reserve before native Security calls, which can block or reenter.
        replaced = true
        guard verify(), live, clock() < deadline else { live = false; return false }; replacementAllowed = true; return true
    }
}
