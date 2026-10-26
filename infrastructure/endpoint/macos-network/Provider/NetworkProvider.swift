import Foundation
import NetworkExtension

final class NetworkProvider: NEFilterDataProvider {
    private let lifecycle = NSLock()
    private let holder = try? SourceHolder()
    private var ipc: ProviderListener?
    private func validConfiguration(_ identity: PeerIdentity) -> Bool {
        let c = filterConfiguration
        guard c.filterSockets, !c.filterPackets, c.filterDataProviderBundleIdentifier == identity.provider,
              let v = c.vendorConfiguration, v.count == 5, exactVersion(v["schema"]),
              exactVersion(v["projection_version"]), exactVersion(v["transport_version"]),
              v["source_policy_sha256"] as? String == sourcePolicy,
              (try? PeerIdentity(v["identity"])) == identity else { return false }
        return true
    }
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        lifecycle.lock()
        var locked = true
        do {
            let identity = try PeerIdentity.bundle()
            guard let holder, Bundle.main.bundleIdentifier == identity.provider,
                  validConfiguration(identity), ipc == nil else { throw SourceError.refused }
            let state = try SourceState(handoff: holder.losses)
            let ipc = try ProviderListener(identity: identity, state: state) { [weak self] in self?.validConfiguration(identity) == true }
            _ = holder.replace(state); self.ipc = ipc
            ipc.start()
            let rules: [NEFilterRule] = [
                NEFilterRule(networkRule: NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                    localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .any), action: .filterData),
                NEFilterRule(networkRule: NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                    localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .any), action: .filterData)
            ]
            lifecycle.unlock(); locked = false
            apply(NEFilterSettings(rules: rules, defaultAction: .allow)) { [weak self] error in
                let good = error == nil && holder.contains(state) && self?.validConfiguration(identity) == true
                state.activated(good)
                if !good { ipc.stop() }
                completionHandler(good ? nil : SourceError.refused)
            }
        } catch { if locked { lifecycle.unlock() }; completionHandler(SourceError.refused) }
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let state = holder?.snapshot(), state.received() { state.admit { stream, receipt in try project(flow, stream: stream, receipt: receipt) } }
        let verdict = NEFilterNewFlowVerdict.allow()
        verdict.shouldReport = false
        return verdict
    }
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lifecycle.lock()
        let state = holder?.replace(nil)
        state?.stop(); ipc?.stop(); ipc = nil
        lifecycle.unlock()
        // No consumer wait or traffic pause; pending records are not claimed to
        // be replayable after OS termination. The parent records stream gaps.
        completionHandler()
    }
}
