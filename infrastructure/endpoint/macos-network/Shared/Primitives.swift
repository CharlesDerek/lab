import Foundation
import Darwin
import Security

enum SourceError: Error { case refused }
let sourcePolicy = "faf8a5d37afe9cdc39b09b3562832b0db72b9c0b03281dd1ce701fc889f1dc64"
let queueRecordLimit = 2048
let queueByteLimit = 8 * 1024 * 1024
let originalByteLimit = 49152
let frameLimit = 1048576
let controlLimit = 4096

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func randomBytes() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw SourceError.refused }
    return Data(bytes)
}
func sourceReceiptClock() throws -> (Int64, Int64) {
    var time = timespec()
    guard clock_gettime(CLOCK_REALTIME, &time) == 0, time.tv_sec > 0,
          time.tv_nsec >= 0, time.tv_nsec < 1_000_000_000 else { throw SourceError.refused }
    return (Int64(time.tv_sec), Int64(time.tv_nsec))
}
func milliseconds() -> UInt64 {
    guard let t = try? sourceReceiptClock(), let s = UInt64(exactly: t.0), s <= (UInt64.max - 999) / 1000 else { return 0 }
    return s * 1000 + UInt64(t.1 / 1_000_000)
}
func json(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
}
