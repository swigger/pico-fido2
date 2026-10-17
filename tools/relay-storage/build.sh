#!/bin/sh
# Build PicoFidoStorage for Linux/macOS. Mirrors build.ps1: verified pinned
# dependencies, a reproducible static binary and packaged license/notice texts.
# Usage: ./build.sh [OUTPUT_DIRECTORY]   (default ../../build/native-relay/Release)
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${1:-"$root/../../build/native-relay/Release"}
mkdir -p -- "$destination"
destination=$(CDPATH= cd -- "$destination" && pwd)
final="$destination/PicoFidoStorage"
temporary="$destination/PicoFidoStorage.build-$$-$(date +%s)"
trap 'rm -f -- "$temporary"' EXIT INT TERM

cd -- "$root"
# Pure Go: the keyring is reached over D-Bus (Linux) or /usr/bin/security (macOS).
export CGO_ENABLED=0
go mod verify || { echo 'Go dependency verification failed.' >&2; exit 1; }
go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$temporary" ./cmd/relay-storage-helper ||
	{ echo 'Storage helper build failed.' >&2; exit 1; }
modules=$(go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' ./cmd/relay-storage-helper) ||
	{ echo 'Cannot identify linked dependency licenses.' >&2; exit 1; }
modules=$(printf '%s\n' "$modules" | grep -v '^pico-fido2/' | grep -v '^$' | LC_ALL=C sort -u)

licenses="$destination/PicoFidoStorage-LICENSES"
mkdir -p -- "$licenses"
manifest="$destination/PicoFidoStorage-THIRD_PARTY.txt.tmp"
{
	echo 'PicoFidoStorage statically linked dependencies. Source versions are pinned in go.mod/go.sum.'
	echo 'rclone 1.75.2: MIT; etcd client 3.6.16: Apache-2.0. Embedded etcd server is test-only.'
	echo 'Complete license/notice texts for each linked module are in PicoFidoStorage-LICENSES.'
	echo 'The program protects its profiles with a key kept in the OS keyring (Secret Service or macOS Keychain). No Go runtime installation is needed to run it.'
	echo ''
} >"$manifest"
printf '%s\n' "$modules" | while IFS='|' read -r path version dir; do
	[ -n "$path" ] && [ -n "$version" ] && [ -d "$dir" ] || { echo 'Unexpected Go module metadata.' >&2; exit 1; }
	folder=$(printf '%s@%s' "$path" "$version" | sed 's/[^a-zA-Z0-9.@_-]/_/g')
	found=0
	for notice in "$dir"/*; do
		name=$(basename -- "$notice")
		[ -f "$notice" ] || continue
		if printf '%s\n' "$name" | grep -Eiq '^(LICENSE|LICENCE|COPYING|NOTICE|AUTHORS)(\.|$)'; then
			mkdir -p -- "$licenses/$folder"
			cp -f -- "$notice" "$licenses/$folder/$name"
			found=1
		fi
	done
	[ "$found" = 1 ] || { echo "No upstream license found for $path." >&2; exit 1; }
	echo "$path $version -> $folder" >>"$manifest"
done
goroot=$(go env GOROOT)
# Homebrew keeps the Go license one level above GOROOT (libexec).
golicense=$goroot/LICENSE; [ -f "$golicense" ] || golicense=$goroot/../LICENSE
cp -f -- "$golicense" "$licenses/GO-LICENSE.txt"
{ echo ''; go version; } >>"$manifest"
cp -f -- "$root/../../LICENSE" "$licenses/PROJECT-LICENSE.txt"
cp -f -- "$root/go.mod" "$licenses/go.mod"
cp -f -- "$root/go.sum" "$licenses/go.sum"
mv -f -- "$manifest" "$destination/PicoFidoStorage-THIRD_PARTY.txt"

# Keep a running user's previous executable. Never terminate it to publish a build.
if [ -e "$final" ]; then
	mv -- "$final" "$final.retired-$(date +%Y%m%d-%H%M%S)-$$"
fi
chmod 0755 "$temporary"
mv -- "$temporary" "$final"
"$final" --version || { echo 'Built storage helper did not report its version.' >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$final"; else shasum -a 256 -- "$final"; fi
