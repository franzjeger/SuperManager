#!/bin/bash
# Run the actual Swift resolver/models and XCTest cases without launching the
# app, its helper, or its daemon. No scaffolding replaces production model code.
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/supermanager-host-index.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/Sources/SuperManagerMac" "$test_dir/Tests/SuperManagerMacTests"
cp "$repo_dir/SuperManagerMac/SuperManagerMac/App/HostIndex.swift" "$test_dir/Sources/SuperManagerMac/"
cp "$repo_dir/SuperManagerMac/SuperManagerMac/Models/SshHost.swift" "$test_dir/Sources/SuperManagerMac/"
cp "$repo_dir/SuperManagerMac/SuperManagerMac/Models/ProvisioningModels.swift" "$test_dir/Sources/SuperManagerMac/"
cp "$repo_dir/SuperManagerMac/SuperManagerMacTests/HostIndexTests.swift" "$test_dir/Tests/SuperManagerMacTests/"
cp "$repo_dir/SuperManagerMac/SuperManagerMacTests/DeploymentOutcomeTests.swift" "$test_dir/Tests/SuperManagerMacTests/"
cat > "$test_dir/Package.swift" <<'PACKAGE'
// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "HostIndexSafety", platforms: [.macOS(.v14)], targets: [
    .target(name: "SuperManagerMac"),
    .testTarget(name: "SuperManagerMacTests", dependencies: ["SuperManagerMac"])
])
PACKAGE
swift test --package-path "$test_dir"
