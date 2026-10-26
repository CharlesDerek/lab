import Foundation
import Security

struct PeerIdentity: Equatable {
    let team: String
    let agent: String
    let container: String
    let provider: String
    let group: String
    let service: String
    var dictionary: [String: String] {
        ["team_id": team, "agent_identifier": agent, "container_identifier": container,
         "provider_identifier": provider, "app_group": group, "mach_service_name": service]
    }
    init(_ raw: Any?) throws {
        guard let d = raw as? [String: String], d.count == 6,
              let team = d["team_id"], let agent = d["agent_identifier"],
              let container = d["container_identifier"], let provider = d["provider_identifier"],
              let group = d["app_group"], let service = d["mach_service_name"],
              team.utf8.count == 10, team.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              [agent, container, provider, group, service].allSatisfy(Self.identifier),
              Set([agent, container, provider]).count == 3, service.hasPrefix(group + ".") else { throw SourceError.refused }
        self.team = team; self.agent = agent; self.container = container; self.provider = provider
        self.group = group; self.service = service
    }
    static func identifier(_ s: String) -> Bool {
        guard (s as NSString).length <= 255, s.contains(".") else { return false }
        return s.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 63 && part.utf8.allSatisfy {
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
            }
        }
    }
    func requirement(identifier: String) throws -> String {
        guard Self.identifier(identifier) else { throw SourceError.refused }
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
        var result: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &result) == errSecSuccess,
              result != nil else { throw SourceError.refused }
        return text
    }
    static func bundle() throws -> PeerIdentity {
        guard Bundle.main.object(forInfoDictionaryKey: "AXNetworkPolicy") as? String == sourcePolicy else { throw SourceError.refused }
        return try PeerIdentity(Bundle.main.object(forInfoDictionaryKey: "AXNetworkIdentity"))
    }
}

func exactVersion(_ value: Any?) -> Bool {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
          ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: n.objCType)) else { return false }
    return n.uint64Value == 1
}
