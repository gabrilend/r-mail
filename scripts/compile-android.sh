#!/bin/sh
# compile-android.sh — build and/or deploy the Android app
#
# Usage:
#   scripts/compile-android.sh           # build + push (default)
#   scripts/compile-android.sh --test    # build only
#   scripts/compile-android.sh --push    # push only (uses last build)
#   scripts/compile-android.sh --push -s SERIAL   # push to a specific device
#
# When multiple devices are connected and no -s flag is given, adb will
# error out and list them. Pick one and pass it with -s.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APK="$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"

ADB=""
if [ -x /etc/profiles/per-user/ritz/bin/adb ]; then
    ADB=/etc/profiles/per-user/ritz/bin/adb
elif command -v adb >/dev/null 2>&1; then
    ADB=adb
fi

do_test=false
do_push=false
adb_serial=""

while [ $# -gt 0 ]; do
    case "$1" in
        --test) do_test=true ;;
        --push) do_push=true ;;
        -s)     shift; adb_serial="$1" ;;
        *)      echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

# Default: both
if ! $do_test && ! $do_push; then
    do_test=true
    do_push=true
fi

if $do_test; then
    echo "Building..."
    cd "$ROOT/android" && ./gradlew assembleDebug
    if [ $? -ne 0 ]; then
        echo "Build failed."
        exit 1
    fi
    echo ""
fi

if $do_push; then
    if [ -z "$ADB" ]; then
        echo "adb not found. Install the Android SDK platform-tools."
        exit 1
    fi

    if [ ! -f "$APK" ]; then
        echo "APK not found at $APK"
        echo "Run with --test first to build."
        exit 1
    fi

    ADB_CMD="$ADB"
    if [ -n "$adb_serial" ]; then
        ADB_CMD="$ADB -s $adb_serial"
    fi

    echo "Installing to device..."
    $ADB_CMD install -r "$APK"
    if [ $? -ne 0 ]; then
        echo ""
        echo "Install failed. If multiple devices are connected, specify one:"
        $ADB devices -l 2>/dev/null | tail -n +2 | grep -v '^$'
        echo ""
        echo "Usage: $0 --push -s SERIAL"
        exit 1
    fi
fi
