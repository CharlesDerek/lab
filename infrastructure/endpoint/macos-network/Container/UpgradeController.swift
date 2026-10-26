import Foundation
import NetworkExtension
import SystemExtensions

final class UpgradeController: NSObject, OSSystemExtensionRequestDelegate {
    private let queue = DispatchQueue(label: "com.athernex.network.upgrade")
    private let identity: PeerIdentity
    private let update: (String, Bool) -> Void
    private var connection: UpgradeConnection?
    private var plan: UpgradePlanValue?
    private var digest = ""
    private var request: OSSystemExtensionRequest?
    private var propertiesRequest = false
    private var afterTerminal = false
    private var guardState: UpgradeAttemptGuard?
    private var permit: [String: Any]?
    private var claimStarted: ContinuousClock.Instant?
    private var reportQueue: [(String, Bool)] = []
    private var reporting = false
    private var reportSequence: UInt64 = 0
    private var terminal = false
    private var stopped = false
    init(identity: PeerIdentity, update: @escaping (String, Bool) -> Void) { self.identity = identity; self.update = update }
    func begin() { queue.async { self.connect() } }
    private func status(_ text: String, finished: Bool = false) { DispatchQueue.main.async { self.update(text, finished) } }
    private func fail() {
        guard !stopped else { return }; stopped = true; guardState?.retire(); connection?.close(); connection = nil
        status("Upgrade not confirmed. Use the root transaction recovery command before another change.", finished: true)
    }
    private func connect() {
        do {
            let c = try UpgradeConnection(identity: identity, queue: queue); connection = c
            c.lost = { [weak self] in self?.fail() }
            c.request(["type": "plan"]) { [weak self] result in
                guard let self, !self.stopped else { return }
                do {
                    let reply = try upgradeObject(result.get(), keys: ["type", "plan", "plan_sha256"])
                    guard reply["type"] as? String == "plan" else { throw UpgradeFailure.refused }
                    let p = try UpgradePlanValue(reply["plan"], identity: self.identity)
                    self.digest = try upgradeHex(reply["plan_sha256"], count: 64)
                    guard AXUpgradeCurrentContainer(self.identity.dictionary, p.containerHashes) else { throw UpgradeFailure.refused }
                    self.plan = p; self.queryProperties()
                } catch { self.fail() }
            }
        } catch { fail() }
    }
    private func queryProperties() {
        guard !stopped else { return }
        propertiesRequest = true
        let r = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: identity.provider, queue: queue)
        request = r; r.delegate = self; OSSystemExtensionManager.shared.submitRequest(r)
        status("Inspecting the registered provider and current filter state.")
    }
    private func property(_ p: OSSystemExtensionProperties) throws -> [String: Any] {
        guard p.url.isFileURL, p.url.path.utf8.count <= 4096, !p.url.path.utf8.contains(0),
              p.bundleIdentifier == identity.provider else { throw UpgradeFailure.refused }
        _ = try upgradeVersion(p.bundleVersion); _ = try upgradeVersion(p.bundleShortVersion)
        return ["url": p.url.path, "bundle_identifier": p.bundleIdentifier, "bundle_version": p.bundleVersion,
                "bundle_short_version": p.bundleShortVersion, "is_enabled": p.isEnabled,
                "is_awaiting_user_approval": p.isAwaitingUserApproval, "is_uninstalling": p.isUninstalling]
    }
    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        guard !stopped, propertiesRequest, request === self.request, properties.count <= 4 else { fail(); return }
        do {
            let rows = try properties.map(property)
            // Retire this exact read-only request before asynchronous preferences.
            self.request = nil; propertiesRequest = false
            NEFilterManager.shared().loadFromPreferences { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    guard !self.stopped, error == nil else { self.fail(); return }
                    let manager = NEFilterManager.shared(); let state: [String: Any]
                    if let c = manager.providerConfiguration {
                        let v = c.vendorConfiguration
                        if c.filterSockets && !c.filterPackets && c.filterDataProviderBundleIdentifier == self.identity.provider,
                           (try? PeerIdentity(v?["identity"])) == self.identity,
                           v?.count == 5, exactVersion(v?["schema"]), exactVersion(v?["projection_version"]),
                           exactVersion(v?["transport_version"]), v?["source_policy_sha256"] as? String == sourcePolicy {
                            state = ["type": "owned", "enabled": manager.isEnabled]
                        } else { state = ["type": "foreign"] }
                    } else { state = ["type": "absent"] }
                    self.inspect(rows, state)
                }
            }
        } catch { fail() }
    }
    private func inspect(_ rows: [[String: Any]], _ filter: [String: Any]) {
        connection?.request(["type": "inspect", "properties": rows, "filter": filter]) { [weak self] result in
            guard let self, !self.stopped, let plan = self.plan else { return }
            do {
                let reply = try upgradeObject(result.get(), keys: ["type"])
                guard reply["type"] as? String == "inspected" else { throw UpgradeFailure.refused }
                if self.afterTerminal || !plan.submit {
                    self.stopped = true; self.connection?.close(); self.connection = nil
                    self.status("Provider inspection recorded. The root transaction must verify and finalize the deployment.", finished: true)
                } else { self.claim() }
            } catch { self.fail() }
        }
    }
    private func claim() {
        guard let plan, plan.submit, claimStarted == nil else { fail(); return }
        // Start locally BEFORE the RPC: a delayed Permit cannot extend the root
        // grant by starting its cutoff only when the response arrives.
        let started = ContinuousClock.now; claimStarted = started
        connection?.request(["type": "claim", "plan_sha256": digest]) { [weak self] result in
            guard let self, !self.stopped else { return }
            do {
                let reply = try upgradeObject(result.get(), keys: ["type", "permit"])
                guard reply["type"] as? String == "permit" else { throw UpgradeFailure.refused }
                let permit = try upgradeObject(reply["permit"], keys: ["plan", "old_property", "attempt_id", "attempt_nonce", "permit_ms"])
                guard let returned = permit["plan"] as? [String: Any], NSDictionary(dictionary: returned).isEqual(to: plan.raw) else { throw UpgradeFailure.refused }
                _ = try upgradeHex(permit["attempt_id"], count: 64); _ = try upgradeHex(permit["attempt_nonce"], count: 64)
                let ms = try upgradeUInt(permit["permit_ms"])
                let guardState = try UpgradeAttemptGuard(claimStarted: started, permitMilliseconds: ms)
                self.permit = permit; self.guardState = guardState
                guard AXUpgradeCurrentContainer(self.identity.dictionary, plan.containerHashes), self.connection?.isLive == true, guardState.submit() else { throw UpgradeFailure.refused }
                self.propertiesRequest = false
                let r = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: self.identity.provider, queue: self.queue)
                self.request = r; r.delegate = self
                OSSystemExtensionManager.shared.submitRequest(r)
                self.status("Waiting for the approved provider upgrade and any system approval.")
            } catch { self.fail() }
        }
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        guard !stopped, !terminal, !propertiesRequest, connection?.isLive == true, request === self.request, let plan, let permit, let guardState else { return .cancel }
        let allowed = guardState.replace {
            guard let old = try? self.property(existing), let new = try? self.property(replacement),
                  let approvedOld = permit["old_property"] as? [String: Any], NSDictionary(dictionary: old).isEqual(to: approvedOld),
                  AXUpgradeCurrentContainer(self.identity.dictionary, plan.containerHashes),
                  AXUpgradeVerifyProperty(old, self.identity.dictionary, plan.old.raw, true),
                  AXUpgradeVerifyProperty(new, self.identity.dictionary, plan.new.raw, false),
                  self.connection?.isLive == true else { return false }; return true
        }
        report(allowed ? "replacement_allowed" : "replacement_refused", terminal: false)
        return allowed ? .replace : .cancel
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        guard !stopped, !terminal, !propertiesRequest, request === self.request else { return }
        report("awaiting_approval", terminal: false); status("Approve the exact pending extension request in System Settings.")
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard !stopped, request === self.request else { return }
        if propertiesRequest { fail(); return }; report("failed", terminal: true)
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard !stopped, !propertiesRequest, request === self.request, !terminal else { return }
        let outcome: String
        switch result {
        case .completed: outcome = guardState?.replacementAllowed == true ? "completed" : "unexpected_completed"
        case .willCompleteAfterReboot: outcome = "reboot_required"
        @unknown default: outcome = "unexpected_completed"
        }
        report(outcome, terminal: true)
    }
    private func report(_ outcome: String, terminal isTerminal: Bool) {
        guard !stopped, !terminal, reportQueue.count < 8 else { fail(); return }
        if isTerminal { terminal = true; guardState?.retire() }
        reportQueue.append((outcome, isTerminal)); sendReport()
    }
    private func sendReport() {
        guard !stopped, !reporting, !reportQueue.isEmpty, let permit, reportSequence < UInt64.max else { return }
        reporting = true; reportSequence += 1; let next = reportQueue.removeFirst()
        connection?.request(["type": "report", "attempt_id": permit["attempt_id"]!, "attempt_nonce": permit["attempt_nonce"]!,
                             "sequence": reportSequence, "outcome": next.0]) { [weak self] result in
            guard let self, !self.stopped else { return }
            do {
                let reply = try upgradeObject(result.get(), keys: ["type"])
                guard reply["type"] as? String == "recorded" else { throw UpgradeFailure.refused }
                self.reporting = false
                if next.1 { self.afterTerminal = true; self.queryProperties() } else { self.sendReport() }
            } catch { self.fail() }
        }
    }
}
