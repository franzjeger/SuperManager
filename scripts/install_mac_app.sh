#!/bin/bash
set -e
./SuperManagerMac/build.sh --release > /dev/null 2>&1
BUILD_DIR="$(xcodebuild -project SuperManagerMac/SuperManager.xcodeproj -scheme SuperManagerMac -configuration Release -showBuildSettings 2>/dev/null | awk '/^[[:space:]]*BUILT_PRODUCTS_DIR =/ { print $3 }')"
APP="$BUILD_DIR/SuperManagerMac.app"
rm -rf "/Applications/SuperManager.app"
cp -R "$APP" "/Applications/SuperManager.app"
