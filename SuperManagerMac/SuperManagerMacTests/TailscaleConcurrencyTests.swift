import XCTest
@testable import SuperManagerMac

final class TailscaleConcurrencyTests: XCTestCase {
    func testConcurrentReadersRetainAndReplaceCachedURLSafely() {
        let cache = TailscaleClient.BinaryCache()
        let initial = URL(fileURLWithPath: "/Example.app/Contents/Resources/tailscale-bin/0")
        XCTAssertEqual(cache.resolve { _ in initial }, initial)
        DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
            _ = cache.resolve { previous in
                let count = Int(previous!.lastPathComponent)!
                return previous!.deletingLastPathComponent().appendingPathComponent(String(count + 1))
            }
        }
        XCTAssertEqual(cache.resolve { $0 }?.lastPathComponent, "1000")
    }

    func testMissingBinaryCanBeDiscoveredLater() {
        let cache = TailscaleClient.BinaryCache()
        XCTAssertNil(cache.resolve { _ in nil })
        let installed = URL(fileURLWithPath: "/Example.app/Contents/Resources/tailscale-bin/tailscale")
        XCTAssertEqual(cache.resolve { _ in installed }, installed)
        XCTAssertEqual(cache.resolve { $0 }, installed)
    }
}
