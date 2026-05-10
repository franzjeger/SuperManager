#!/usr/bin/env bash
# Build SuperManager for macOS.
#
# What this script does
# ---------------------
# 1. (Re)generates `SuperManager.xcodeproj` from `project.yml` via
#    xcodegen, so the project file always reflects what's in source
#    control. The `.xcodeproj` itself is .gitignored.
# 2. Builds the app via `xcodebuild`. Xcode's build phases handle:
#    - compiling the Swift GUI
#    - running `cargo build --release` for the two Rust binaries
#      (user-space daemon + privileged helper)
#    - copying both Rust binaries into `Contents/MacOS/`
#    - re-signing the daemon with its own (empty) entitlements
#    - re-signing the helper with its own (empty) entitlements
#    - re-sealing the bundle with the app's `keychain-access-groups`
#      entitlement
#
# What this script does NOT do
# ----------------------------
# - Open the app. Pass `--run` to do that.
# - Install in /Applications. Bundle stays in DerivedData.
# - Notarise. We're using an `Apple Development` cert (Personal Team),
#   which can't be notarised — only `Developer ID Application` certs
#   from a paid membership can. When that membership lands, this
#   script gets a `notarise` step.
#
# Prerequisites
# -------------
# - Xcode (with the user logged in via Settings → Accounts so xcodebuild
#   can fetch a Personal Team provisioning profile on demand)
# - xcodegen (`brew install xcodegen`)
# - Rust toolchain (`rustup`/`cargo`)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Args
RUN_AFTER=0
CONFIG="Debug"
CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --run)     RUN_AFTER=1 ;;
        --release) CONFIG="Release" ;;
        --clean)   CLEAN=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

# Check tools
for tool in xcodegen xcodebuild cargo; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not found in PATH" >&2
        case "$tool" in
            xcodegen) echo "  Install: brew install xcodegen" >&2 ;;
            xcodebuild) echo "  Install: Xcode from App Store" >&2 ;;
            cargo) echo "  Install: https://rustup.rs/" >&2 ;;
        esac
        exit 1
    fi
done

echo "→ Generating Xcode project from project.yml…"
xcodegen generate

if [[ $CLEAN -eq 1 ]]; then
    echo "→ Cleaning previous build artefacts…"
    xcodebuild -project SuperManager.xcodeproj \
        -scheme SuperManagerMac \
        -configuration "$CONFIG" \
        clean
fi

echo "→ Building ($CONFIG)…"
# `-allowProvisioningUpdates` lets Xcode contact Apple's servers to
# refresh the Personal Team provisioning profile (it expires every 7
# days). Without this, builds fail one week after the cert was issued.
xcodebuild -project SuperManager.xcodeproj \
    -scheme SuperManagerMac \
    -configuration "$CONFIG" \
    -destination 'platform=macOS' \
    -allowProvisioningUpdates \
    build \
    | xcbeautify --quieter 2>/dev/null \
    || xcodebuild -project SuperManager.xcodeproj \
        -scheme SuperManagerMac \
        -configuration "$CONFIG" \
        -destination 'platform=macOS' \
        -allowProvisioningUpdates \
        build \
        2>&1 | tail -30
# (Pipe-with-fallback: prefer xcbeautify if installed, else dump tail
# of raw xcodebuild output. xcbeautify isn't required.)

# Resolve the .app path from xcodebuild's settings — works regardless of
# Xcode's DerivedData layout shenanigans.
BUILD_DIR="$(xcodebuild -project SuperManager.xcodeproj \
    -scheme SuperManagerMac \
    -configuration "$CONFIG" \
    -showBuildSettings 2>/dev/null \
    | awk '/^[[:space:]]*BUILT_PRODUCTS_DIR =/ { print $3 }')"
APP="$BUILD_DIR/SuperManagerMac.app"

echo ""
echo "→ Built: $APP"
echo ""
echo "Embedded entitlements (app):"
codesign -d --entitlements - "$APP" 2>/dev/null \
    | grep -E "keychain-access-groups|application-identifier" \
    || true

if [[ $RUN_AFTER -eq 1 ]]; then
    echo ""
    echo "→ Killing any running instance and relaunching…"
    pkill -f SuperManagerMac 2>/dev/null || true
    pkill -f supermgrd-mac 2>/dev/null || true
    rm -f "$HOME/Library/Application Support/SuperManager/supermgrd.sock"
    sleep 1
    open "$APP"
fi
