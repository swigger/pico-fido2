[CmdletBinding()]
param(
    [ValidatePattern('^COM[0-9]+$')][string]$Port,
    [string]$PackageDirectory = '',
    [string]$Python = '',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This updater is deliberately application-only. Never erase_flash, change
# eFuses, write a factory image or overwrite the device's partition table.
if (!$PackageDirectory) {
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'firmware')) {
        $PackageDirectory = $PSScriptRoot
    } else {
        throw 'Specify -PackageDirectory containing firmware/ and manifest.json.'
    }
}
$PackageDirectory = (Resolve-Path -LiteralPath $PackageDirectory).Path
$firmwareDirectory = Join-Path $PackageDirectory 'firmware'
$manifest = Get-Content -LiteralPath (Join-Path $PackageDirectory 'manifest.json') -Raw | ConvertFrom-Json
$imageName = 'app.bin'
$imagePath = Join-Path $firmwareDirectory $imageName
$partitionPath = Join-Path $firmwareDirectory 'partition-table.bin'
foreach ($fileName in @($imageName, 'partition-table.bin')) {
    $filePath = Join-Path $firmwareDirectory $fileName
    $expectedHash = $manifest.files.PSObject.Properties[$fileName].Value
    if (!$expectedHash -or (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw "Package hash mismatch: $fileName"
    }
}
$imageLength = (Get-Item -LiteralPath $imagePath).Length
if ($imageLength -le 0 -or $imageLength -gt 0x1f0000) { throw 'Application image exceeds the expected partition.' }
$expectedPartition = [IO.File]::ReadAllBytes($partitionPath)
if ($expectedPartition.Length -ne 3072) { throw 'Unexpected partition-table image length.' }
if ($CheckOnly) {
    Write-Host "Package OK: $imageName ($imageLength bytes); device has not been accessed."
    return
}
if (!$Port) { throw 'Specify -Port COMn after holding BOOT while connecting the intended key.' }
if (!$Python) {
    $Python = (Get-Command python -ErrorAction Stop).Source
}
if (!(Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'Python/esptool not found; specify -Python with the ESP-IDF Python executable.' }
$partitionRead = [IO.Path]::GetTempFileName()
try {
    Write-Host "Checking $Port partition layout before writing..."
    & $Python -m esptool --chip esp32s3 --port $Port --baud 460800 --before default_reset --after no_reset read_flash 0x8000 0x1000 $partitionRead
    if ($LASTEXITCODE -ne 0) { throw 'Partition read failed. No firmware was written.' }
    $actualPartition = [IO.File]::ReadAllBytes($partitionRead)
    if ($actualPartition.Length -ne 4096) { throw 'Incomplete partition read. No firmware was written.' }
    for ($i = 0; $i -lt $expectedPartition.Length; $i++) {
        if ($actualPartition[$i] -ne $expectedPartition[$i]) {
            throw 'Device partition layout differs from this build. No firmware was written.'
        }
    }
    Write-Host "Writing $imageName at 0x10000 only; NVS, pairing and credential partitions are preserved."
    & $Python -m esptool --chip esp32s3 --port $Port --baud 460800 --before no_reset --after no_reset write_flash --flash_mode keep --flash_freq keep --flash_size keep --verify 0x10000 $imagePath
    if ($LASTEXITCODE -ne 0) { throw 'Application update did not complete. Keep the package and retry in BOOT mode.' }
    Write-Host 'Application verified. Resetting the device...'
    & $Python -m esptool --chip esp32s3 --port $Port --before no_reset --after watchdog_reset chip_id
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Reset disconnected the serial port; check that the FIDO device reappears. If needed, unplug/replug once.' }
} finally {
    Remove-Item -LiteralPath $partitionRead -Force -ErrorAction SilentlyContinue
}
