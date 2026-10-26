import Foundation

@main
struct UpgradeControls {
    static func main() {
        do { try controls(); print("Network upgrade controls passed; no OS activation or signature proof") }
        catch { fputs("Network upgrade controls failed\n", stderr); exit(1) }
    }
    static func require(_ value: @autoclosure () -> Bool) throws { if !value() { throw UpgradeFailure.refused } }
    static func controls() throws {
        let start = ContinuousClock.now; var now = start
        let late = try UpgradeAttemptGuard(claimStarted: start, permitMilliseconds: 100, clock: { now })
        now = start.advanced(by: .milliseconds(100)); try require(!late.submit())
        now = start
        let valid = try UpgradeAttemptGuard(claimStarted: start, permitMilliseconds: 100, clock: { now })
        try require(valid.submit()); try require(!valid.submit())
        var calls = 0
        try require(valid.replace { calls += 1; return true }); try require(valid.replacementAllowed)
        try require(!valid.replace { calls += 1; return true }); try require(calls == 1)
        let blocked = try UpgradeAttemptGuard(claimStarted: start, permitMilliseconds: 100, clock: { now })
        try require(blocked.submit())
        try require(!blocked.replace { now = start.advanced(by: .milliseconds(100)); return true })
        try require(!blocked.replacementAllowed)
        now = start
        let retired = try UpgradeAttemptGuard(claimStarted: start, permitMilliseconds: 100, clock: { now })
        try require(retired.submit()); try require(!retired.replace { retired.retire(); return true })
        try require(!retired.replacementAllowed)
        let legacy = try upgradeVersion("1"), canonical = try upgradeVersion("1.0.0"); try require(legacy == canonical)
        let invalidNumbers: [Any] = [true, -1, 1.5, "1"]
        for raw in invalidNumbers {
            var rejected = false; do { _ = try upgradeUInt(raw) } catch { rejected = true }; try require(rejected)
        }
        let identity = try PeerIdentity(["team_id": "TESTTEAM00", "agent_identifier": "com.example.agent",
            "container_identifier": "com.example.container", "provider_identifier": "com.example.provider",
            "app_group": "TESTTEAM00.com.example.network", "mach_service_name": "TESTTEAM00.com.example.network.ipc"])
        func pin(_ v: String, _ h: String) -> [String: Any] { ["bundle_version": v, "short_version": "0.1",
            "executable_sha256": String(repeating: h, count: 64), "info_plist_sha256": String(repeating: h, count: 64), "cdhashes": [String(repeating: h, count: 40)]] }
        let p: [String: Any] = ["mode": "submit", "transaction_id": String(repeating: "a", count: 64), "generation": 1,
            "identity": identity.dictionary, "source_policy_sha256": sourcePolicy, "old": pin("1", "a"), "new": pin("2.0.0", "b"), "container_cdhashes": [String(repeating: "c", count: 40)]]
        let plan = try UpgradePlanValue(p, identity: identity); try require(plan.submit)
        var bad = p; bad["mode"] = "replace_anything"
        var refused = false; do { _ = try UpgradePlanValue(bad, identity: identity) } catch { refused = true }; try require(refused)
        bad = p; bad["new"] = pin("1.0.0", "b"); refused = false
        do { _ = try UpgradePlanValue(bad, identity: identity) } catch { refused = true }; try require(refused)
        for text in [#"{"type":"plan","type":"permit"}"#, #"{"plan":1,"\u0070lan":2}"#,
                     #"{"type":"permit","permit":{"attempt_id":"a","attempt_id":"b"}}"#,
                     #"{"type":"plan",}"#] {
            refused = false; do { _ = try UpgradeJSON.decode(Data(text.utf8)) } catch { refused = true }; try require(refused)
        }
        let validBody = try JSONSerialization.data(withJSONObject: ["type": "plan", "plan": p, "plan_sha256": String(repeating: "a", count: 64)])
        let parsed = try UpgradeJSON.decode(validBody); try require(parsed["type"] as? String == "plan")
    }
}
