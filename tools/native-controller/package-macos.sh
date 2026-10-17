#!/bin/sh
# Make a self-contained "Pico FIDO Controller.app" from a CMake build directory:
# Qt frameworks (macdeployqt), PicoFidoStorage in Contents/MacOS (the controller
# only looks beside its own executable), license texts in Contents/Resources,
# then one signature over the whole bundle.
# Usage: tools/native-controller/package-macos.sh BUILD_DIR [CODESIGN_IDENTITY]
#   CODESIGN_IDENTITY defaults to ad-hoc ("-"). Keychain access is tied to the
#   signature, so use the same identity for every build a user runs.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 BUILD_DIR [CODESIGN_IDENTITY]" >&2; exit 2; }
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build=$(CDPATH= cd -- "$1" && pwd)
identity=${2:--}
app="$build/Pico FIDO Controller.app"
[ -d "$app" ] || { echo "No bundle at $app; build Esp32KeyConfirm first." >&2; exit 1; }
qtbin=$(dirname -- "$(command -v macdeployqt 2>/dev/null || echo "$(brew --prefix qtbase 2>/dev/null)/bin/macdeployqt")")
[ -x "$qtbin/macdeployqt" ] || { echo 'macdeployqt not found; add Qt bin to PATH.' >&2; exit 1; }

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT INT TERM
sh "$root/tools/relay-storage/build.sh" "$staging"
cp -f -- "$staging/PicoFidoStorage" "$app/Contents/MacOS/PicoFidoStorage"
rm -rf -- "$app/Contents/Resources/PicoFidoStorage-LICENSES"
cp -R -- "$staging/PicoFidoStorage-LICENSES" "$app/Contents/Resources/"
cp -f -- "$staging/PicoFidoStorage-THIRD_PARTY.txt" "$app/Contents/Resources/"

"$qtbin/macdeployqt" "$app" -always-overwrite
codesign --force --deep --timestamp=none --sign "$identity" "$app"
codesign --verify --deep --strict "$app"
"$app/Contents/MacOS/PicoFidoStorage" --version
echo "Packaged $app"
