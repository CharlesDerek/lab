import Foundation

// One immutable per-connection exported object. Invalidation can retire only
// its own epoch; it cannot clear a later consumer. There is no raw GUI interface.
final class ProviderSession: NSObject, AXNetworkProvider {
    let epoch: UInt64
    private let state: SourceState
    private let scope: () -> Bool
    private let lock = NSLock()
    private var nonce: Data?
    private var lastRequest: UInt64 = 0
    private var detached = false
    private var busy = false
    private var retiring = false
    private var retired = false
    private let release: () -> Void
    init(epoch: UInt64, state: SourceState, scope: @escaping () -> Bool, release: @escaping () -> Void = {}) {
        self.epoch = epoch; self.state = state; self.scope = scope; self.release = release
    }
    func invalidate() {
        lock.lock(); detached = true; retiring = true
        let done = !busy && !retired; if done { retired = true }; lock.unlock()
        if done { release() }
    }
    var registered: Bool { lock.lock(); defer { lock.unlock() }; return nonce != nil && !detached }
    private func fail(_ reply: (Data, Data) -> Void) { reply(Data(), Data()) }
    func hello(_ version: UInt32, nonce: Data, policy: Data, reply: @escaping (Data, Data) -> Void) {
        lock.lock()
        guard !detached, !busy, self.nonce == nil, version == 1, nonce.count == 32,
              policy.count == 32, hex(policy) == sourcePolicy else { lock.unlock(); fail(reply); return }
        busy = true; self.nonce = nonce
        lock.unlock()
        guard scope() else { state.activated(false); finish(reply, result: nil); return }
        let result = try? state.response(epoch: epoch, request: 0, nonce: nonce)
        finish(reply, result: result)
    }
    private func finish(_ reply: (Data, Data) -> Void, result: (Data, Data)?, detach: Bool = false) {
        lock.lock(); let live = !detached; if detach { detached = true }; lock.unlock()
        // Keep the operation lease through reply invocation, including direct
        // reentrant test callbacks. An invalidated old ACK cannot overlap a new
        // consumer registration while still applying its state transition.
        if let result, live { reply(result.0, result.1) } else { fail(reply) }
        lock.lock(); busy = false
        let done = retiring && !retired; if done { retired = true }; lock.unlock()
        if done { release() }
    }
    private func request(_ epoch: UInt64, request: UInt64, nonce: Data, pull: Bool = false,
                         ack: (UInt64, String)? = nil, detach: Bool = false,
                         reply: @escaping (Data, Data) -> Void) {
        lock.lock()
        guard !detached, !busy, self.epoch == epoch, nonce.count == 32, self.nonce == nonce,
              lastRequest < UInt64.max, request == lastRequest + 1 else { lock.unlock(); fail(reply); return }
        lastRequest = request; busy = true; lock.unlock()
        guard scope() else { state.activated(false); finish(reply, result: nil); return }
        let result = try? state.response(epoch: epoch, request: request, nonce: nonce, pull: pull, ack: ack)
        finish(reply, result: result, detach: detach)
    }
    func pull(_ epoch: UInt64, request: UInt64, nonce: Data, reply: @escaping (Data, Data) -> Void) {
        self.request(epoch, request: request, nonce: nonce, pull: true, reply: reply)
    }
    func ack(_ epoch: UInt64, request: UInt64, nonce: Data, batch: UInt64, digest: Data,
             reply: @escaping (Data, Data) -> Void) {
        guard batch > 0, digest.count == 32 else { fail(reply); return }
        self.request(epoch, request: request, nonce: nonce, ack: (batch, hex(digest)), reply: reply)
    }
    func detach(_ epoch: UInt64, request: UInt64, nonce: Data, reply: @escaping (Data, Data) -> Void) {
        self.request(epoch, request: request, nonce: nonce, detach: true, reply: reply)
    }
}

final class ProviderListener: NSObject, NSXPCListenerDelegate {
    private let identity: PeerIdentity
    private let state: SourceState
    private let scope: () -> Bool
    private let lock = NSLock()
    private let requirement: String
    private var listener: NSXPCListener?
    private var connection: NSXPCConnection?
    private var session: ProviderSession?
    private var epoch: UInt64 = 0
    private var stopped = false
    init(identity: PeerIdentity, state: SourceState, scope: @escaping () -> Bool) throws {
        self.identity = identity; self.state = state; self.scope = scope
        requirement = try identity.requirement(identifier: identity.agent)
    }
    func start() {
        let listener = NSXPCListener(machServiceName: identity.service)
        listener.setConnectionCodeSigningRequirement(requirement)
        listener.delegate = self
        self.listener = listener
        listener.resume()
    }
    func stop() {
        lock.lock(); stopped = true; let c = connection, s = session; lock.unlock()
        s?.invalidate(); c?.invalidate(); listener?.invalidate(); listener = nil
    }
    private func retire(_ c: NSXPCConnection, generation: UInt64) {
        lock.lock(); defer { lock.unlock() }
        if epoch == generation, connection === c { connection = nil; session = nil }
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Public connection-bound EUID, not a PID lookup or peer-supplied value.
        guard c.effectiveUserIdentifier == 0 else { return false }
        guard let dataClasses = NSSet(object: NSData.self) as? Set<AnyHashable> else { return false }
        lock.lock()
        guard !stopped, connection == nil, epoch < UInt64.max else { lock.unlock(); return false }
        epoch += 1
        let generation = epoch
        let session = ProviderSession(epoch: generation, state: state, scope: scope) { [weak self, weak c] in
            // Never run retirement inline while connection setup holds lock.
            DispatchQueue.global(qos: .utility).async { [weak self, weak c] in
                if let self, let c { self.retire(c, generation: generation) }
            }
        }
        self.session = session; connection = c
        let interface = NSXPCInterface(with: AXNetworkProvider.self)
        let selectors = [#selector(AXNetworkProvider.hello(_:nonce:policy:reply:)),
            #selector(AXNetworkProvider.pull(_:request:nonce:reply:)),
            #selector(AXNetworkProvider.ack(_:request:nonce:batch:digest:reply:)),
            #selector(AXNetworkProvider.detach(_:request:nonce:reply:))]
        for selector in selectors {
            interface.setClasses(dataClasses, for: selector, argumentIndex: 0, ofReply: true)
            interface.setClasses(dataClasses, for: selector, argumentIndex: 1, ofReply: true)
        }
        interface.setClasses(dataClasses, for: selectors[0], argumentIndex: 1, ofReply: false)
        interface.setClasses(dataClasses, for: selectors[0], argumentIndex: 2, ofReply: false)
        for selector in selectors.dropFirst() { interface.setClasses(dataClasses, for: selector, argumentIndex: 2, ofReply: false) }
        interface.setClasses(dataClasses, for: selectors[2], argumentIndex: 4, ofReply: false)
        c.setCodeSigningRequirement(requirement)
        c.exportedInterface = interface; c.exportedObject = session
        c.invalidationHandler = { [weak session] in
            DispatchQueue.global(qos: .utility).async { [weak session] in session?.invalidate() }
        }
        c.interruptionHandler = { [weak c] in c?.invalidate() }
        c.resume()
        lock.unlock()
        // An approved but silent process cannot reserve the sole consumer slot
        // forever without registering. The agent has the same bounded wait.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { [weak c, weak session] in
            if session?.registered != true { c?.invalidate() }
        }
        return true
    }
}
