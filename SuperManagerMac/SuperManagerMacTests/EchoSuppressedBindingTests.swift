import SwiftUI
import XCTest

@testable import SuperManagerMac

/// Regression tests for the `MenuBarExtra(isInserted:)` launch hang.
///
/// The bug these lock in: handing `MenuBarExtra` a binding that forwards
/// same-value writes makes the app spin at 100% CPU on launch and never
/// finish bootstrapping. `echoSuppressed` is the fix, and it is the kind of
/// wrapper that looks redundant to a reader who wasn't there — so these
/// tests state what breaks if it's removed.
final class EchoSuppressedBindingTests: XCTestCase {

    /// A write of the value already held must not reach the storage.
    /// This is the property that breaks the feedback loop.
    func testSameValueWriteIsDropped() {
        var storage = true
        var writeCount = 0
        let binding = echoSuppressed(Binding(
            get: { storage },
            set: { storage = $0; writeCount += 1 }
        ))

        binding.wrappedValue = true
        binding.wrappedValue = true
        binding.wrappedValue = true

        XCTAssertEqual(writeCount, 0, "same-value writes must not reach storage")
        XCTAssertTrue(storage)
    }

    /// A real change must still propagate — suppressing everything would
    /// leave the Settings toggle just as dead as it was before.
    func testChangedValueIsForwarded() {
        var storage = true
        var writeCount = 0
        let binding = echoSuppressed(Binding(
            get: { storage },
            set: { storage = $0; writeCount += 1 }
        ))

        binding.wrappedValue = false

        XCTAssertEqual(writeCount, 1)
        XCTAssertFalse(storage)
        XCTAssertFalse(binding.wrappedValue, "reads follow the underlying storage")
    }

    /// Alternating writes each count once: the guard compares against the
    /// live value, not a stale snapshot captured at wrap time.
    func testAlternatingWritesEachPropagateOnce() {
        var storage = true
        var writeCount = 0
        let binding = echoSuppressed(Binding(
            get: { storage },
            set: { storage = $0; writeCount += 1 }
        ))

        binding.wrappedValue = false
        binding.wrappedValue = false
        binding.wrappedValue = true
        binding.wrappedValue = true
        binding.wrappedValue = false

        XCTAssertEqual(writeCount, 3)
        XCTAssertFalse(storage)
    }

    /// External changes to the storage are visible through the wrapper —
    /// it holds no cached copy of its own.
    func testReadsReflectExternalStorageChanges() {
        var storage = false
        let binding = echoSuppressed(Binding(
            get: { storage },
            set: { storage = $0 }
        ))

        XCTAssertFalse(binding.wrappedValue)
        storage = true
        XCTAssertTrue(binding.wrappedValue)
    }
}
