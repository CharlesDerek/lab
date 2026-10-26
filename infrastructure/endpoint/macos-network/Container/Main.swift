import AppKit
import NetworkExtension
import SystemExtensions

@main
final class ActivationController: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private var window: NSWindow?
    private let status = NSTextField(labelWithString: "Observations are controlled separately from the endpoint agent.")
    private var identity: PeerIdentity?
    private var busy = false
    private var upgrade: UpgradeController?
    static func main() {
        let app = NSApplication.shared
        let controller = ActivationController()
        app.delegate = controller; app.setActivationPolicy(.regular)
        withExtendedLifetime(controller) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        identity = try? PeerIdentity.bundle()
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 590, height: 280),
                         styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        w.title = "Athernex network observations"
        let enable = NSButton(title: "Enable observations", target: self, action: #selector(enableSource))
        let disable = NSButton(title: "Disable observations", target: self, action: #selector(disableSource))
        let upgrade = NSButton(title: "Continue approved upgrade", target: self, action: #selector(upgradeSource))
        let note = NSTextField(wrappingLabelWithString: "This source reports new socket-flow metadata and allows traffic. Stopping the agent leaves the source running with a bounded buffer. This window cannot view network records.")
        let stack = NSStackView(views: [status, note, enable, disable, upgrade]); stack.orientation = .vertical
        stack.spacing = 12; stack.translatesAutoresizingMaskIntoConstraints = false
        if let content = w.contentView { content.addSubview(stack); NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24)]) }
        enable.isEnabled = identity != nil; disable.isEnabled = identity != nil
        upgrade.isEnabled = identity != nil
        if identity == nil { status.stringValue = "The installed source identity is invalid." }
        window = w; w.center(); w.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    @objc private func enableSource() {
        guard !busy, let identity else { return }
        guard AXUpgradeOrdinaryActionsAllowed() else { finish("An upgrade is pending or its protected state is unavailable."); return }; busy = true
        status.stringValue = "Waiting for system extension approval."
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identity.provider, queue: .main)
        request.delegate = self; OSSystemExtensionManager.shared.submitRequest(request)
    }
    @objc private func disableSource() {
        guard !busy else { return }
        guard AXUpgradeOrdinaryActionsAllowed() else { finish("An upgrade is pending or its protected state is unavailable."); return }
        busy = true; configure(enabled: false)
    }
    @objc private func upgradeSource() {
        guard !busy, let identity else { return }; busy = true
        let controller = UpgradeController(identity: identity) { [weak self] message, finished in
            self?.status.stringValue = message
            if finished { self?.busy = false }
        }
        upgrade = controller; controller.begin()
    }
    private func configure(enabled: Bool) {
        guard let identity else { finish("The installed source identity is invalid."); return }
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                guard error == nil else { self.finish("The filter configuration could not be loaded."); return }
                guard AXUpgradeOrdinaryActionsAllowed() else { self.finish("An upgrade is pending; the filter was left unchanged."); return }
                if let existing = manager.providerConfiguration {
                    guard existing.filterDataProviderBundleIdentifier == identity.provider,
                          (try? PeerIdentity(existing.vendorConfiguration?["identity"])) == identity else {
                        self.finish("A different filter configuration is present; it was left unchanged."); return
                    }
                } else if !enabled { self.finish("This source is already disabled."); return }
                let c = manager.providerConfiguration ?? NEFilterProviderConfiguration()
                c.filterSockets = true; c.filterPackets = false; c.filterDataProviderBundleIdentifier = identity.provider
                c.vendorConfiguration = ["schema": 1, "projection_version": 1, "transport_version": 1,
                    "source_policy_sha256": sourcePolicy, "identity": identity.dictionary]
                manager.providerConfiguration = c; manager.localizedDescription = "Athernex network observations"
                manager.isEnabled = enabled
                manager.saveToPreferences { [weak self] error in DispatchQueue.main.async {
                    self?.finish(error == nil ? (enabled ? "Source enabled. The agent must verify its connection before coverage is ready." : "Source disabled. The installed extension has not been removed.") : "The filter configuration could not be saved.")
                } }
            }
        }
    }
    private func finish(_ message: String) { busy = false; status.stringValue = message }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { status.stringValue = "Approve the requested extension in System Settings to continue." }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish("The extension request failed.") }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result { case .completed: configure(enabled: true)
        case .willCompleteAfterReboot: finish("Restart the Mac to finish the extension request, then enable observations.")
        @unknown default: finish("The extension request returned an unsupported result.") }
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        status.stringValue = "Replacing an installed provider requires a separately approved upgrade."
        return .cancel
    }
}
