#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
cd -- "$(dirname -- "$0")"
umask 077
chmod 700 ./athernex-endpoint
native_hash=''
native_check=''
if [ -e ./native-adapter.required ]; then
  native_hash=$(./athernex-endpoint installer-native-hash ./release.json)
  [ -n "$native_hash" ] || { echo 'Native adapter metadata is missing.' >&2; exit 1; }
  [ -f ./athernex-endpoint-native ] || { echo 'The declared native adapter is missing.' >&2; exit 1; }
  native_check=$(mktemp -d /private/tmp/athernex-native.XXXXXXXX)
  native_pending=''
  trap 'rm -rf -- "$native_check"; [ -z "$native_pending" ] || rm -f -- "$native_pending"' EXIT
  trap 'exit 1' HUP INT TERM
  native_sum=$(/usr/bin/shasum -a 256 ./athernex-endpoint-native)
  [ "${native_sum%% *}" = "$native_hash" ] || { echo 'Native adapter checksum mismatch.' >&2; exit 1; }
  cp ./athernex-endpoint-native "$native_check/adapter"
  copied_sum=$(/usr/bin/shasum -a 256 "$native_check/adapter")
  [ "${copied_sum%% *}" = "$native_hash" ] || { echo 'Native adapter changed during verification.' >&2; exit 1; }
  for binary in ./athernex-endpoint "$native_check/adapter"; do
    /usr/bin/codesign --verify --strict --verbose=2 "$binary"
    /usr/sbin/spctl --assess --type execute "$binary"
  done
  /usr/bin/codesign -d --entitlements :- "$native_check/adapter" > "$native_check/entitlements.plist"
  entitlement=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.endpoint-security.client' "$native_check/entitlements.plist")
  [ "$entitlement" = true ] || { echo 'Endpoint Security entitlement is missing.' >&2; exit 1; }
  debug_entitlement=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.get-task-allow' "$native_check/entitlements.plist" 2>/dev/null || true)
  [ -z "$debug_entitlement" ] || [ "$debug_entitlement" = false ] || { echo 'Debug-entitled native adapters cannot be installed.' >&2; exit 1; }
elif [ -e ./athernex-endpoint-native ]; then
  echo 'The native adapter is not declared in this release.' >&2; exit 1
fi
./athernex-endpoint installer-check /Library/AthernexEndpoint/state ./athernex-endpoint
if launchctl print system/com.athernex.endpoint >/dev/null 2>&1; then
  launchctl bootout system/com.athernex.endpoint
fi
./athernex-endpoint installer-check /Library/AthernexEndpoint/state ./athernex-endpoint --stopped
mkdir -p /Library/AthernexEndpoint
chmod 700 /Library/AthernexEndpoint
cp ./athernex-endpoint /Library/AthernexEndpoint/athernex-endpoint
cp ./athernex-endpoint /Library/AthernexEndpoint/athernex-controller
chmod 700 /Library/AthernexEndpoint/athernex-endpoint
chmod 700 /Library/AthernexEndpoint/athernex-controller
if [ -n "$native_hash" ]; then
  # Same-filesystem staging keeps an existing adapter intact until the complete
  # verified replacement is ready. Authorization starts under the controller.
  native_pending=$(mktemp /Library/AthernexEndpoint/.native.XXXXXXXX)
  cp "$native_check/adapter" "$native_pending"
  chmod 700 "$native_pending"
  mv -f "$native_pending" /Library/AthernexEndpoint/athernex-endpoint-native
fi
/Library/AthernexEndpoint/athernex-endpoint enroll ./bootstrap.json /Library/AthernexEndpoint/state
if [ -n "$native_hash" ]; then
  # Pin the already verified helper independently of scanner/protection setup.
  # This preserves the existing telemetry enablement policy.
  /Library/AthernexEndpoint/athernex-endpoint configure-macos-process-adapter /Library/AthernexEndpoint/state /Library/AthernexEndpoint/athernex-endpoint-native "$native_hash"
  /Library/AthernexEndpoint/athernex-endpoint configure-macos-authentication-adapter /Library/AthernexEndpoint/state /Library/AthernexEndpoint/athernex-endpoint-native "$native_hash"
fi
/Library/AthernexEndpoint/athernex-endpoint provision-antivirus ./bootstrap.json /Library/AthernexEndpoint/state
if [ -n "$native_hash" ]; then
  /Library/AthernexEndpoint/athernex-endpoint configure-native-protection /Library/AthernexEndpoint/state /Library/AthernexEndpoint/athernex-endpoint-native
fi
cat > /Library/LaunchDaemons/com.athernex.endpoint.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.athernex.endpoint</string>
<key>ProgramArguments</key><array><string>/Library/AthernexEndpoint/athernex-controller</string><string>supervise</string><string>/Library/AthernexEndpoint/state</string><string>/Library/AthernexEndpoint/athernex-endpoint</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>15</integer><key>Umask</key><integer>63</integer>
</dict></plist>
PLIST
chmod 644 /Library/LaunchDaemons/com.athernex.endpoint.plist
launchctl bootstrap system /Library/LaunchDaemons/com.athernex.endpoint.plist
rm -- ./bootstrap.json
echo 'Installed. Configure ClamAV paths and approved folders in /Library/AthernexEndpoint/state/config.json. Existing protection is preserved.'
if [ -n "$native_hash" ]; then
  echo 'Native scanner setup is prepared. The controller starts enabled protection; Endpoint Security authorization and Full Disk Access must be granted on this Mac. Native real-time protection remains unverified until live blocking is proven.'
fi
