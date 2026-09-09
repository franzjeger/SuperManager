// One-time migration tool. Run only after disconnecting regular-channel VPNs.
// Must run inside a signed com.sybr.supermanager app bundle containing the
// original Contents/Library/LaunchDaemons/com.sybr.supermanager.helper.plist.
// No registration, data migration, network setup, or arbitrary service control.
import Foundation
import ServiceManagement

let service = SMAppService.daemon(plistName: "com.sybr.supermanager.helper.plist")
print("Regular helper registration before: \(service.status.rawValue)")
do {
    if service.status != .notRegistered {
        try service.unregister()
    }
    print("Regular helper registration after: \(service.status.rawValue)")
    guard service.status == .notRegistered else { exit(1) }
} catch {
    fputs("Regular helper unregistration failed: \(error)\n", stderr)
    exit(1)
}
