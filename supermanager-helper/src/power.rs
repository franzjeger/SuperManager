//! Helper-side macOS sleep/wake handling via IOKit power notifications.
//!
//! ## Why this exists
//!
//! The SwiftUI app fires `system_sleep` / `system_wake` RPCs from
//! `NSWorkspace` notifications, but those only arrive while the app is
//! running. When the operator quits the app (or it isn't open) and the
//! machine sleeps with a tunnel up, nothing tears the tunnel down — on wake
//! its stale full-tunnel routes black-hole all traffic. The helper is a
//! root LaunchDaemon that outlives the GUI, so it registers for power
//! notifications directly and owns teardown itself.
//!
//! ## Mechanism (`IORegisterForSystemPower`)
//!
//! IOKit delivers power events on a CoreFoundation run loop, so we run a
//! dedicated thread spinning `CFRunLoopRun()`. The C callback fires for:
//!
//!   - `kIOMessageCanSystemSleep`   — a chance to veto *idle* sleep. We never
//!     veto; we acknowledge with `IOAllowPowerChange` so idle sleep proceeds.
//!   - `kIOMessageSystemWillSleep`  — sleep is committed. We synchronously
//!     tear down VPNs, then MUST call `IOAllowPowerChange` or the machine
//!     stalls until the kernel's deadline (~30 s) forces sleep anyway.
//!   - `kIOMessageSystemHasPoweredOn` — the machine woke. We run the same
//!     post-wake cleanup as the `system_wake` RPC.
//!
//! ## Safety contract
//!
//! The single hard rule: **always call `IOAllowPowerChange` on
//! WillSleep/CanSystemSleep**, on every path. We bound the teardown with an
//! 8 s timeout so a wedged `swanctl` can never starve the acknowledgement —
//! and even if it somehow did, the kernel force-sleeps at its own deadline,
//! so the worst case is a bounded delay, never a permanent block.

use std::os::raw::{c_int, c_long, c_void};

// mach_port_t / io_object_t / io_connect_t are all `mach_port_t` == u32.
type IoObjectT = u32;
type IoConnectT = u32;
type IoServiceT = u32;
type IONotificationPortRef = *mut c_void;
type CFRunLoopSourceRef = *mut c_void;
type CFRunLoopRef = *mut c_void;
type CFStringRef = *const c_void;

/// `IOServiceInterestCallback`:
/// `void (*)(void *refcon, io_service_t service, uint32_t msgType, void *msgArg)`
type IOServiceInterestCallback =
    extern "C" fn(*mut c_void, IoServiceT, u32, *mut c_void);

#[allow(non_upper_case_globals)]
mod msg {
    // <IOKit/pwr_mgt/IOPMLib.h> / <IOKit/IOMessage.h>
    pub const kIOMessageCanSystemSleep: u32 = 0xE000_0270;
    pub const kIOMessageSystemWillSleep: u32 = 0xE000_0280;
    pub const kIOMessageSystemHasPoweredOn: u32 = 0xE000_0300;
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        the_port_ref: *mut IONotificationPortRef,
        callback: IOServiceInterestCallback,
        notifier: *mut IoObjectT,
    ) -> IoConnectT;
    fn IONotificationPortGetRunLoopSource(notify: IONotificationPortRef) -> CFRunLoopSourceRef;
    fn IOAllowPowerChange(kernel_port: IoConnectT, notification_id: c_long) -> c_int;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRun();
    static kCFRunLoopCommonModes: CFStringRef;
}

/// Lives for the daemon's lifetime (intentionally leaked). Holds the root
/// power port needed to acknowledge sleep, plus a Tokio handle so the C
/// callback can drive the async teardown on the run-loop thread.
struct PowerContext {
    root_port: IoConnectT,
    handle: tokio::runtime::Handle,
}

/// Run the VPN teardown, bounded so the sleep acknowledgement is never
/// starved. Best-effort: every underlying step swallows its own errors.
///
/// `block_on` is driven by the multi-thread Tokio runtime's worker threads
/// (`#[tokio::main]` + `features = ["full"]`), so parking this CFRunLoop
/// thread inside it does not stall the async work. If the runtime flavor were
/// ever switched to current-thread, this would deadlock — keep it multi-thread.
///
/// `catch_unwind`: we're called from an `extern "C"` callback; a panic
/// unwinding across the FFI boundary into CoreFoundation is undefined
/// behavior. Contain it so the WillSleep path always reaches the mandatory
/// `IOAllowPowerChange` that follows this call.
fn teardown_for_sleep(ctx: &PowerContext) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.handle.block_on(async {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(8), async {
                crate::strongswan::terminate_and_sweep().await;
                let _ = crate::openvpn::terminate_all().await;
            })
            .await;
        });
    }));
}

/// Post-wake cleanup. Bounded + panic-contained for the same reasons as
/// `teardown_for_sleep`: it runs on the CFRunLoop thread (a hung sweep would
/// stall later power callbacks) and must not unwind across the FFI boundary.
fn cleanup_after_wake(ctx: &PowerContext) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.handle.block_on(async {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                crate::route_guardian::reset_snapshot();
                crate::strongswan::sweep_stale_configs().await;
            })
            .await;
        });
    }));
}

extern "C" fn power_callback(
    refcon: *mut c_void,
    _service: IoServiceT,
    msg_type: u32,
    msg_arg: *mut c_void,
) {
    // SAFETY: `refcon` is the leaked `*mut PowerContext` we passed to
    // IORegisterForSystemPower; it outlives the program.
    let ctx: &PowerContext = unsafe { &*(refcon as *const PowerContext) };

    match msg_type {
        msg::kIOMessageCanSystemSleep => {
            // Don't veto idle sleep — acknowledge so it proceeds.
            unsafe { IOAllowPowerChange(ctx.root_port, msg_arg as c_long) };
        }
        msg::kIOMessageSystemWillSleep => {
            tracing::info!("power: system will sleep — tearing down VPNs");
            teardown_for_sleep(ctx);
            // CONTRACT: always allow the sleep, even if teardown timed out.
            unsafe { IOAllowPowerChange(ctx.root_port, msg_arg as c_long) };
            tracing::info!("power: sleep acknowledged");
        }
        msg::kIOMessageSystemHasPoweredOn => {
            tracing::info!("power: system woke — running post-wake cleanup");
            cleanup_after_wake(ctx);
        }
        _ => {}
    }
}

/// Register for system power notifications and spin a dedicated CFRunLoop
/// thread to receive them. Idempotent-ish — only call once at startup.
/// On failure (e.g. sandboxed test env) it logs and returns; the Swift-app
/// RPCs and the wall-clock wake detector remain as fallbacks.
pub fn spawn_power_monitor() {
    let handle = tokio::runtime::Handle::current();
    let _ = std::thread::Builder::new()
        .name("sm-power".into())
        .spawn(move || unsafe {
            // Leak the context: the callback needs it for the whole daemon
            // lifetime, and the daemon only exits on SIGTERM/replace.
            let ctx = Box::into_raw(Box::new(PowerContext { root_port: 0, handle }));

            let mut notify_port: IONotificationPortRef = std::ptr::null_mut();
            let mut notifier: IoObjectT = 0;
            let root_port = IORegisterForSystemPower(
                ctx as *mut c_void,
                &mut notify_port,
                power_callback,
                &mut notifier,
            );
            // MACH_PORT_NULL == 0 means registration failed.
            if root_port == 0 || notify_port.is_null() {
                tracing::warn!("power: IORegisterForSystemPower failed — relying on GUI RPC + wake detector");
                drop(Box::from_raw(ctx));
                return;
            }
            // Backfill the port the callback needs to acknowledge sleep.
            (*ctx).root_port = root_port;

            let source = IONotificationPortGetRunLoopSource(notify_port);
            CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
            tracing::info!("power: registered for system power notifications");
            // Blocks this thread forever, delivering callbacks.
            CFRunLoopRun();
        });
}
