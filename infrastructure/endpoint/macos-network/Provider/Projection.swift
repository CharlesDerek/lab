import Foundation
import NetworkExtension
import Darwin

func numericEndpoint(host: String, port: String, family: Int32) throws -> [String: Any] {
    // Bound the UTF16 backing length before enumerating/copying UTF8 bytes.
    guard (host as NSString).length <= 80, (port as NSString).length <= 5, !host.utf8.contains(0),
          !port.isEmpty, port.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let number = UInt16(port), [AF_INET, AF_INET6].contains(family) else { throw SourceError.refused }
    var address = host
    if address.first == "[", address.last == "]" { address.removeFirst(); address.removeLast() }
    let parts = address.split(separator: "%", omittingEmptySubsequences: false)
    guard parts.count <= 2, !parts[0].isEmpty else { throw SourceError.refused }
    var scope: UInt32?
    if parts.count == 2 {
        guard family == AF_INET6, !parts[1].isEmpty, parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let parsed = UInt32(parts[1]) else { throw SourceError.refused }
        scope = parsed
    }
    address = String(parts[0])
    var storage = [UInt8](repeating: 0, count: 16)
    let parsed = address.withCString { string in storage.withUnsafeMutableBytes { inet_pton(family, string, $0.baseAddress) } }
    guard parsed == 1 else { throw SourceError.refused }
    var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let rendered = storage.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &text, socklen_t(text.count)) }
    guard rendered != nil else { throw SourceError.refused }
    return ["address": String(cString: text), "port": number, "scope_id": scope.map { $0 as Any } ?? NSNull()]
}
func endpoint(_ value: NWEndpoint?, family: Int32) throws -> Any {
    guard let value else { return NSNull() }
    guard let host = value as? NWHostEndpoint else { throw SourceError.refused }
    return try numericEndpoint(host: host.hostname, port: host.port, family: family)
}
func token(_ value: Data?) throws -> Any {
    guard let value else { return NSNull() }
    guard value.count == 32 else { throw SourceError.refused }
    return hex(value)
}
func selectedProjection(stream: String, receipt: UInt64, flowID: String, direction: Int32,
    family: Int32, type: Int32, proto: Int32, local: Any, remote: Any,
    application: Any, process: Any, time: (Int64, Int64)) throws -> Data {
    guard [0, 1, 2].contains(direction), [AF_INET, AF_INET6].contains(family),
          ((proto == 0 && [SOCK_STREAM, SOCK_DGRAM].contains(type)) ||
           (proto == IPPROTO_TCP && type == SOCK_STREAM) || (proto == IPPROTO_UDP && type == SOCK_DGRAM)),
          receipt > 0, time.0 > 0, time.1 >= 0, time.1 < 1_000_000_000 else { throw SourceError.refused }
    let data = try json(["projection_version": 1, "stream_id": stream, "receipt_sequence": receipt,
        "callback": "new_flow", "receipt_time": ["seconds": time.0, "nanoseconds": time.1],
        "flow_id": flowID.lowercased(), "direction": direction, "socket_family": family,
        "socket_type": type, "socket_protocol": proto, "local": local, "remote": remote,
        "source_app_audit_token_hex": application, "source_process_audit_token_hex": process])
    guard data.count <= originalByteLimit else { throw SourceError.refused }
    return data
}
func project(_ flow: NEFilterFlow, stream: String, receipt: UInt64) throws -> Data? {
    guard let socket = flow as? NEFilterSocketFlow else { return nil }
    let family = socket.socketFamily, proto = socket.socketProtocol, type = socket.socketType
    guard [AF_INET, AF_INET6].contains(family), [0, IPPROTO_TCP, IPPROTO_UDP].contains(proto) else { return nil }
    guard let direction = Int32(exactly: flow.direction.rawValue) else { throw SourceError.refused }
    return try selectedProjection(stream: stream, receipt: receipt, flowID: flow.identifier.uuidString,
        direction: direction, family: family, type: type, proto: proto,
        local: endpoint(socket.localEndpoint, family: family), remote: endpoint(socket.remoteEndpoint, family: family),
        application: token(flow.sourceAppAuditToken), process: token(flow.sourceProcessAuditToken), time: clock())
}
