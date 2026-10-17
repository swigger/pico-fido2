# Relay configuration protocol v1

Implemented in `shared/relay_config.*`, `shared/relay_setup.*`, `shared/relay_hid.*`,
`src/fido2/relay_firmware.c` and `tools/native-controller/relay_control.*`.
Overview and operating rules: [relay.md](relay.md).

## Authenticated reboot

The status report's optional tail contains `MGT1` at payload offset 50 and
capability bits at 54: bit 0 signed reboot, bit 1 development diagnostics. Older
firmware leaves these bytes zero. Reports 20/21 remain device public-key reads.

Reboot uses feature reports 22/23, with the same 63-byte payload convention.
SET 22 opcode 1 at offset 0 begins a transaction: a nonzero 16-byte transaction
ID at 1, then zero padding. GET 22 returns `PRS1` at 0, phase at 4 (0 idle,
1 challenge, 2 accepted, 3 failed), result at 5 (0 OK, 1 invalid, 2 busy,
3 unauthorized, 4 expired), signature-half count at 6, transaction ID at 8 and
the 32-byte fresh nonce at 24 (challenge phase only).

The paired controller signs SHA-256 over `pico-fido2 device restart v1` including
its NUL, device serial (16 bytes), transaction ID (16), controller key ID (16),
and device nonce (32). SET 23 supplies signature halves in order: index 0/1 at
0, transaction at 1, 32 signature bytes at 17, zero padding. SET 22 opcode 2
executes: transaction at 1, controller ID at 17, zero padding. The signature
uses raw P-256 `r || s`. A challenge expires after 10 seconds. Successful
verification consumes it and publishes accepted status before a 500 ms delayed
software reset. Replayed requests cannot postpone or repeat that reset.

An active authenticator operation, pairing or setup rejects/cancels reboot;
queue overflow cancels it as well. No BOOT press is required for this signed
command. RNG, signature verification and reset run on the application task,
with USB callbacks limited to enqueueing and snapshots. It does not erase
credentials, pairings or saved configuration. These reports remain present
when `ENABLE_RELAY_DIAGNOSTICS=OFF`.

## Development diagnostics

`ENABLE_RELAY_DIAGNOSTICS=ON` enables a 32-event RAM ring and feature report 24
on firmware, and `--device-diagnostics` on the CLI. Both builds default to OFF;
release builds omit the recorder, report and CLI command. No flash writes or
previous-boot history are retained. Only numeric USB/CTAP/network metadata is
recorded. The fixed record is defined in `shared/relay_diagnostics.h`; `PDG2`
pages use a transaction ID and a frozen snapshot. Reboot remains available
independently of this option.

## Trust and activation

Initialization uses the separate USB vendor HID collection (usage page 0xff31,
usage 1). Every feature report is 64 bytes including its report ID; offsets below
refer to the 63-byte payload. The standard FIDO interface and the USB serial keep
their identities. Local display names are never part of configuration or FIDO
messages.

The host must sign with a currently paired controller key. The device generates
a fresh 32-byte challenge. P-256 ECDSA signs SHA-256 over the concatenation:

1. ASCII `pico-fido2 relay setup v1`, including its NUL terminator.
2. The 16-byte ASCII device USB serial.
3. The 16-byte host transaction ID.
4. The 16-byte controller key ID (pairing fingerprint).
5. The 32-byte device challenge.
6. The four-byte little-endian configuration length.
7. The exact configuration bytes.

The signature is raw `r || s` (32 bytes each); the domain is distinct from
request-approval signatures. After verification the device requires BOOT release,
a fresh press of at least one second, and release. Authorization is
checked again immediately before saving. Setup expires after 120 seconds; another
authenticator operation or pairing cancels it. Terminal states wipe the staged
configuration, signature and challenge.

TinyUSB callbacks only enqueue SET messages or read published status snapshots.
Crypto, button processing and NVS run on the application task.
Queue overflow cancels the staged setup. No USB command simulates BOOT.

The running configuration is immutable until reboot. NVS namespace `fido_relay`
holds `initialized=1` and the versioned `config_v1` blob; the marker is committed
before the first blob. An absent marker and blob mean legacy local-only behavior;
partial, malformed or unreadable storage blocks credential operations. After
commit the firmware reads the blob back, compares it and publishes its SHA-256.
An ambiguous write blocks operations until a validated reboot, even if a later
write succeeds. Neither setup nor mode switching erases the FIDO storage partition
or controller keys.

## Configuration encoding

All integers are unsigned little-endian. This is a byte format, not a C struct.

| Offset | Size | Content |
| --- | --- | --- |
| 0 | 8 | ASCII `PF2RCF03` |
| 8 | 1 | Mode: 0 local-only, 1 relay-only |
| 9 | 1 | Network count, 0–10 (relay mode requires at least one) |
| 10 | variable | Network records in priority order |

Each network record contains SSID length, password length, host length, a zero
reserved byte, a two-byte port, then SSID/password/host bytes without terminators.
Limits are 32/190/253 bytes. A password is empty (open Wi-Fi), 8–63 printable
ASCII bytes, exactly 64 hexadecimal bytes (raw PSK), or a `PF2PW1` sealed token.
Plaintext is never longer than 64 bytes; the larger wire field exists so a
configuration read can return a token.

A token is `PF2PW1` followed by the lowercase hex of a 12-byte nonce, the
AES-256-GCM ciphertext (same length as the plaintext) and a 16-byte tag. The
key is derived from the device's own P-256 key with a purpose-separated HMAC, and
the associated data binds the device USB serial. The controller can recognize
and preserve a token but cannot open it. A token from another device or a
modified token fails authentication. The device seals a plaintext password when
`读取设备` builds the read snapshot; a token is left unchanged when written back.
Devices that have never been read still store plaintext, so a read followed by a
write migrates them to sealed tokens.

Hosts are ASCII DNS names or IP literals; IPv6 is unbracketed. URLs, paths,
userinfo, zone identifiers and control characters are rejected. Ports are
1–65535. The maximum encoding is 4820 bytes.

Local mode may retain dormant network profiles. The configuration holds no trust
material: the network worker trusts a safe end whose per-run TLS certificate is
signed by a paired controller key, and proves the device with its own device key
(see the relay reference). Older `PF2RCF01`/`PF2RCF02` blobs are rejected.

## SET reports

Every SET starts with opcode at offset 0, four-byte sequence at 1, transaction ID
(16 bytes) at 5. Begin uses sequence 1; later packets must increment without gaps
or repetition. The host waits for each acknowledgment before sending the next.

| Report | Opcode | Fields starting at offset 21 |
| --- | --- | --- |
| 16 | 1 (begin) | Configuration length LE16; zero padding |
| 16 | 0 (cancel) | Zero padding |
| 16 | 5 (read page) | Offset LE16; zero padding |
| 17 | 2 (data) | Offset LE16, length byte, 1–39 data bytes, zero padding |
| 18 | 3 (signature) | Half index (0 then 1), 32 signature bytes, zero padding |
| 19 | 4 (seal) | Controller key ID (16 bytes), zero padding |

Chunks must be contiguous. Signature halves follow the complete configuration.
Seal triggers validation; only physical confirmation triggers persistence.
Unknown reports, malformed frames, stale transactions and reordered packets never
write configuration. The client cancels its own transaction on upload failure.
A read page request uses sequence 1 and is rejected while a setup transaction is
active. Offset 0 starts a new snapshot; later offsets must name the same
transaction and stay within that snapshot.

## GET reports

Reports 16–18 begin with ASCII `PRL1`; the configuration page report begins with
`PRD1`. Unused bytes are zero. No GET returns a plaintext Wi-Fi password or
credential/account data. Report 19 returns the mode, SSIDs, hosts and ports plus
sealed `PF2PW1` password tokens, which the controller can preserve but not
decrypt.

| Report | Fields |
| --- | --- |
| 16 | phase[4], setup result[5], running/stored modes[6/7], running/stored counts[8/9], flags[10], configuration version[11], acknowledged sequence LE32[12], transaction[16..31], received/expected lengths LE16[32/34], remaining milliseconds LE32[36], command result[40], signature-half count[41]; firmware diagnostics: ASCII `NET1`[42..45], network phase[46], Wi-Fi disconnect reason[47], network flags[48], profile index[49] |
| 17 | transaction[4..19], challenge[20..51], expected length LE16[52], remaining milliseconds LE32[54] |
| 18 | saved configuration SHA-256[4..35], flags[36] |
| 19 | ASCII `PRD1`[0..3], transaction[4..19], total length LE16[20..21], offset LE16[22..23], page length[24], 38 data bytes[25..62] |

Report 19 is idempotent for the selected offset: the host may retry a page
without advancing a cursor. The page length is 1–38, or 0 exactly at the end.
The host reads the stored configuration, not the running one, so a successful
write is visible before reboot.

Read/token support is a protocol extension. Older firmware ignores a read-page
SET and has no GET 19; older firmware also rejects a token-length password field,
so update the firmware and controller together. A controller that does not know
GET 19 simply ignores the new report and keeps writing plaintext as before.

Flag bits: 1 storage available, 2 boot/storage fault, 4 reboot required. Network
flags: 1 Wi-Fi started, 2 associated, 4 IPv4 address, 8 IPv6 address. Network
phases: 1 Wi-Fi init, 2 connecting, 3 waiting for address, 4 resolving/connecting
to the safe end, 5 time bootstrap, 6 TLS handshake, 7 sending, 8 waiting for the
safe end, 9 done. Setup phase and error enums are authoritative in `relay_setup.h`
and `relay_hid.h`. The UI reports success only when the saved digest matches the
host's exact configuration and the reboot flag is set.

## Local isolation

The relay/fault boundary precedes all local CBOR handlers, including PIN, GetInfo,
reset, credential management and vendor commands. The common APDU dispatcher also
blocks local U2F, management, OpenPGP and OATH access. Automatic OTP button actions
are disabled while relay mode or configuration setup is active. HID INIT advertises
NMSG outside local mode. HID channel initialization and application selection obey
the mode gate, so they cannot initialize local FIDO files. APDU GET RESPONSE is
gated before its continuation path and clears saved response state. The mode is
loaded before startup flash scanning; relay/fault scans do not write directory
markers.

In relay mode only CTAP commands `0x01`, `0x02`, `0x04`, `0x06`, `0x08` and vendor
command `0x50` (exact RP/account query) are forwarded through the Wi-Fi/TLS worker.
Credential management `0x0a`/`0x41` returns `CTAP2_ERR_NO_CREDENTIALS` locally and
never enumerates either store; all other commands return `CTAP1_ERR_INVALID_COMMAND`.
Transport errors fail closed and are never dispatched to local storage.
