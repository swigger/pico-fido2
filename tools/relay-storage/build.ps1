[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../build/native-relay/Release'))
$ErrorActionPreference = 'Stop'
$destination = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$temporaryExe = Join-Path $destination ('PicoFidoStorage.build-' + [guid]::NewGuid().ToString('N') + '.exe')
$finalExe = Join-Path $destination 'PicoFidoStorage.exe'
Push-Location $PSScriptRoot
try {
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Go dependency verification failed.' }
    & go build -trimpath -buildvcs=false -ldflags '-s -w' -o $temporaryExe ./cmd/relay-storage-helper
    if ($LASTEXITCODE -ne 0) { throw 'Storage helper build failed.' }
    $modules = & go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' ./cmd/relay-storage-helper
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify linked dependency licenses.' }
    $modules = $modules | Where-Object { $_ -and -not $_.StartsWith('pico-fido2/') } | Sort-Object -Unique
    $licenseRoot = Join-Path $destination 'PicoFidoStorage-LICENSES'
    New-Item -ItemType Directory -Path $licenseRoot -Force | Out-Null
    $manifest = [Collections.Generic.List[string]]::new()
    $manifest.Add('PicoFidoStorage statically linked dependencies. Source versions are pinned in go.mod/go.sum.')
    $manifest.Add('rclone 1.75.2: MIT; etcd client 3.6.16: Apache-2.0. Embedded etcd server is test-only.')
    $manifest.Add('Complete license/notice texts for each linked module are in PicoFidoStorage-LICENSES.')
    $manifest.Add('The program uses Windows DPAPI/CNG system APIs. No Python or Go runtime installation is needed to run it.')
    $manifest.Add('')
    foreach ($entry in $modules) {
        $part = $entry.Split('|')
        if ($part.Count -ne 3) { throw 'Unexpected Go module metadata.' }
        $notices = Get-ChildItem -LiteralPath $part[2] -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|AUTHORS)(\.|$)' }
        if (-not $notices) { throw "No upstream license found for $($part[0])." }
        $moduleFolder = ($part[0] + '@' + $part[1]) -replace '[^a-zA-Z0-9.@_-]', '_'
        $target = Join-Path $licenseRoot $moduleFolder
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        foreach ($notice in $notices) { Copy-Item -LiteralPath $notice.FullName -Destination (Join-Path $target $notice.Name) -Force }
        $manifest.Add($part[0] + ' ' + $part[1] + ' -> ' + $moduleFolder)
    }
    $goRootPath = & go env GOROOT
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the Go toolchain license.' }
    Copy-Item -LiteralPath (Join-Path $goRootPath 'LICENSE') -Destination (Join-Path $licenseRoot 'GO-LICENSE.txt') -Force
    $goVersion = & go version
    $manifest.Add(''); $manifest.Add($goVersion)
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../../LICENSE') -Destination (Join-Path $licenseRoot 'PROJECT-LICENSE.txt') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'go.mod') -Destination (Join-Path $licenseRoot 'go.mod') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'go.sum') -Destination (Join-Path $licenseRoot 'go.sum') -Force
    [IO.File]::WriteAllLines((Join-Path $destination 'PicoFidoStorage-THIRD_PARTY.txt'), $manifest, [Text.UTF8Encoding]::new($false))
    # Keep a running user's previous executable. Never terminate it to publish a build.
    if (Test-Path -LiteralPath $finalExe) {
        $retired = $finalExe + '.retired-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
        Move-Item -LiteralPath $finalExe -Destination $retired
    }
    Move-Item -LiteralPath $temporaryExe -Destination $finalExe
    & $finalExe --version
    if ($LASTEXITCODE -ne 0) { throw 'Built storage helper did not report its version.' }
    Get-FileHash -LiteralPath $finalExe -Algorithm SHA256
} finally { Pop-Location }
