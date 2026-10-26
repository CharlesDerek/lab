import Foundation
import Security

// All operations and callbacks are serialized on the owning controller queue.
// Framework decoding/allocation is outside the 32KiB application copy bound.
final class UpgradeConnection {
    private let queue: DispatchQueue
    private let connection: NSXPCConnection
    private var pending: ((Result<[String: Any], Error>) -> Void)?
    private var serial: UInt64 = 0
    private var closed = false
    private let lifetime = NSLock()
    private var invalidated = false
    var isLive: Bool { lifetime.lock(); defer { lifetime.unlock() }; return !invalidated }
    var lost: (() -> Void)?
    init(identity: PeerIdentity, queue: DispatchQueue) throws {
        self.queue = queue
        let service = identity.group + ".network-upgrade"
        guard service.utf8.count < 128 else { throw UpgradeFailure.refused }
        connection = NSXPCConnection(machServiceName: service, options: .privileged)
        let interface = NSXPCInterface(with: AXNetworkUpgrade.self)
        let classes = NSSet(object: NSData.self) as! Set<AnyHashable>
        interface.setClasses(classes, for: #selector(AXNetworkUpgrade.request(_:reply:)), argumentIndex: 0, ofReply: false)
        interface.setClasses(classes, for: #selector(AXNetworkUpgrade.request(_:reply:)), argumentIndex: 0, ofReply: true)
        connection.remoteObjectInterface = interface
        connection.setCodeSigningRequirement(try identity.requirement(identifier: identity.agent))
        connection.invalidationHandler = { [weak self] in self?.markLost() }
        connection.interruptionHandler = { [weak self] in self?.markLost() }
        connection.resume()
    }
    func request(_ body: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        guard !closed, isLive, pending == nil, serial < UInt64.max,
              let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]), !data.isEmpty, data.count <= 32768 else {
            completion(.failure(UpgradeFailure.refused)); fail(); return
        }
        serial += 1; let token = serial; pending = completion
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] _ in self?.markLost() } as? AXNetworkUpgrade
        guard let proxy else { fail(); return }
        proxy.request(data) { [weak self] reply in
            guard let self else { return }
            // Do not copy an over-bound body. Foundation owns its received object.
            guard !reply.isEmpty, reply.count <= 32768 else { self.queue.async { self.fail() }; return }
            self.queue.async {
                guard !self.closed, self.serial == token, let callback = self.pending else { return }
                guard let object = try? UpgradeJSON.decode(reply) else { self.fail(); return }
                self.pending = nil; callback(.success(object))
            }
        }
        queue.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, self.serial == token, self.pending != nil else { return }; self.fail()
        }
    }
    private func fail() {
        guard !closed else { return }; closed = true
        lifetime.lock(); invalidated = true; lifetime.unlock()
        let callback = pending; pending = nil; connection.invalidate()
        callback?(.failure(UpgradeFailure.refused)); lost?()
    }
    private func markLost() {
        // Mark independently of the delegate queue. A blocking Security call
        // must observe owner loss before it can return a replacement decision.
        lifetime.lock(); invalidated = true; lifetime.unlock()
        queue.async { [weak self] in self?.fail() }
    }
    func close() { lifetime.lock(); invalidated = true; lifetime.unlock(); closed = true; pending = nil; connection.invalidate() }
    deinit { connection.invalidate() }
}
