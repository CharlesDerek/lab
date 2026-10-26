import Foundation

// JSONSerialization collapses duplicate object keys. Scan the bounded original
// bytes first, decoding each key as a JSON string so escaped aliases also refuse.
// Foundation remains responsible for full JSON scalar/Unicode grammar checking.
struct UpgradeJSON {
    private let bytes: [UInt8]
    private var at = 0
    private var nodes = 0
    static func decode(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 32768 else { throw UpgradeFailure.refused }
        var scan = UpgradeJSON(bytes: Array(data)); try scan.value(depth: 0); scan.space()
        guard scan.at == scan.bytes.count,
              let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw UpgradeFailure.refused }
        return result
    }
    private mutating func space() { while at < bytes.count && [9, 10, 13, 32].contains(bytes[at]) { at += 1 } }
    private mutating func take(_ byte: UInt8) throws { space(); guard at < bytes.count, bytes[at] == byte else { throw UpgradeFailure.refused }; at += 1 }
    private mutating func string() throws -> String {
        space(); let start = at; try take(34)
        while at < bytes.count {
            let byte = bytes[at]; at += 1
            if byte == 34 {
                let data = Data(bytes[start..<at])
                guard let result = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String else { throw UpgradeFailure.refused }; return result
            }
            if byte < 32 { throw UpgradeFailure.refused }
            if byte == 92 { guard at < bytes.count else { throw UpgradeFailure.refused }; at += 1 }
        }
        throw UpgradeFailure.refused
    }
    private mutating func value(depth: Int) throws {
        nodes += 1; space()
        guard depth <= 16, nodes <= 1024, at < bytes.count else { throw UpgradeFailure.refused }
        switch bytes[at] {
        case 123:
            at += 1; space(); var keys = Set<String>()
            if at < bytes.count, bytes[at] == 125 { at += 1; return }
            while true {
                let key = try string(); guard keys.insert(key).inserted else { throw UpgradeFailure.refused }
                try take(58); try value(depth: depth + 1); space()
                guard at < bytes.count else { throw UpgradeFailure.refused }
                if bytes[at] == 125 { at += 1; return }; try take(44)
            }
        case 91:
            at += 1; space(); if at < bytes.count, bytes[at] == 93 { at += 1; return }
            while true {
                try value(depth: depth + 1); space(); guard at < bytes.count else { throw UpgradeFailure.refused }
                if bytes[at] == 93 { at += 1; return }; try take(44)
            }
        case 34: _ = try string()
        default:
            let start = at
            while at < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[at]) { at += 1 }
            guard at > start else { throw UpgradeFailure.refused }
        }
    }
}
