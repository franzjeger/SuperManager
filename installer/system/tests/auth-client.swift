import Darwin
import Foundation
// No privileged operations: connect, wait for the authorization fixture response.
let fd = socket(AF_UNIX, SOCK_STREAM, 0)
guard fd >= 0 else { exit(2) }
defer { close(fd) }
var address = sockaddr_un()
address.sun_family = sa_family_t(AF_UNIX)
let path = Array(CommandLine.arguments[1].utf8CString)
guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else { exit(2) }
withUnsafeMutableBytes(of: &address.sun_path) { target in
    path.withUnsafeBytes { source in target.copyBytes(from: source) }
}
let result = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}
guard result == 0 else { exit(3) }
var response = [UInt8](repeating: 0, count: 64)
let length = Darwin.read(fd, &response, response.count)
guard length > 0, String(bytes: response.prefix(length), encoding: .utf8) == "authorized\n" else { exit(4) }
