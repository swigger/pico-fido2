# Relay mode reference

The ESP32-S3 build with `ENABLE_REMOTE_PRESENCE=ON` can run in one of two modes.
In local mode it is an ordinary FIDO2 key whose BOOT press can be replaced by a
signed confirmation from a paired controller. In relay mode the hardware stores no
usable credentials: it forwards CTAP requests over Wi-Fi/TLS to a "safe end" (the
native controller running on a computer you trust), which holds the private keys
and asks for explicit approval of every operation. Requirements: `new_design.md`;
build: `tools/native-controller/BUILD.txt`; wire formats:
[relay-provisioning.md](relay-provisioning.md), [relay-storage-pipe.md](relay-storage-pipe.md).

## Architecture

| Layer | Component | Role |
| --- | --- | --- |
| Hardware | ESP32-S3 firmware (`src/fido2/relay_*.c`, `shared/*.c`) | Standard USB FIDO HID to the host (PC, iPhone); vendor HID collection for pairing/configuration; Wi-Fi/TLS client in relay mode |
| Network | TLS 1.2 to the safe end, pinned to a paired controller key | Up to ten Wi-Fi + host/port profiles; one TCP connection per CTAP request |
| Safe end | `tools/native-controller` (`Esp32KeyConfirm` GUI, `pico-fido-cli`) | Encrypted credential vault, ES256 authenticator, ClientPIN, approval dialogs, TLS listener, backup, cloud storage |
| Storage helper | `tools/relay-storage` (`PicoFidoStorage`, Go) | rclone OneDrive/Google Drive/WebDAV transfers and etcd coordination for cloud vaults |

The controller core is portable C++17 (Mbed TLS 3.6.7, hidapi 0.15.0) with a Qt
Widgets UI (Qt 6 or 5.15). It builds on Windows and Linux; macOS support is
prepared but untested. All windows and CLI commands run as the same OS user that
owns the data.

### Local data

Per-user data directory: `%LOCALAPPDATA%\PicoFido2Remote` (Windows),
`~/Library/Application Support/PicoFido2Remote` (macOS),
`$XDG_DATA_HOME/PicoFido2Remote` or `~/.local/share/PicoFido2Remote` (Linux).

Secret files use the extension `<ext>`: `.dpapi` on Windows (DPAPI, bound to the
Windows user), `.sealed` elsewhere. Sealed files are
`"PF2SEAL1" | nonce[12] | AES-256-GCM ciphertext | tag[16]` under one random 256-bit
key per user kept in the OS keyring (Secret Service via libsecret, or Keychain);
the magic and a per-file-kind purpose label are authenticated. Without a reachable
keyring every protected read or write fails; there is no plaintext fallback.

| Path (under the data directory) | Content |
| --- | --- |
| `controller-v2<ext>` | Controller P-256 key (pairing identity); older copies kept as timestamped backups |
| `device-names/<serial>.name` | Local display names (UTF-8, max 32 bytes); never sent to the device |
| `relay-settings/<serial><ext>` | Encrypted device-settings draft (a recoverable copy only) |
| `relay-devices/<serial><ext>` | Device public key saved by BOOT pairing; the safe end's trust record for that device |
| `safe-end/credentials-v1<ext>` and `credentials-v1<ext>.lock` | Local vault and its identity/lock marker; keep both together |
| `safe-end/backend-v1<ext>` and `backend-v1.lock` | Persistent storage selection (local, cloud, unbound, pending) |
| `safe-end/cloud-<namespace>.generation` | Rollback guard for a cloud vault |
| `safe-end/cloud-code-<namespace><ext>` | Optional remembered recovery code, OS-protected and bound to this storage identity and namespace |
| `safe-end/cloud/<namespace><ext>` | Storage-helper profile (provider credentials, coordinator identity) |

Files are created only by explicit actions; a missing or corrupt initialized file
is never replaced by an empty default. Locks are exclusive OS file locks and
coordinate processes on one computer only.

## Modes and switching

- Mode 0 "仅自存储（默认）": local credentials, local PIN, optional controller confirmation.
- Mode 1 "仅中转（私钥与批准操作在安全端）": every credential operation goes to the safe end.

An unconfigured device behaves like the original firmware. The mode is part of
the signed configuration, takes effect after a reboot and is immutable while
running. Switching never erases the FIDO partition, local PIN or pairings: local
credentials stay dormant in relay mode and return after switching back. There is
no merging and no fallback: if the safe end is unreachable a relay request fails
(CTAP `0x30`) and is never answered from local storage.

In relay mode the firmware dispatcher blocks every local path before any handler
runs: local CBOR handlers (GetInfo, PIN, reset, credential management, vendor),
U2F/APDU, management, OpenPGP and OATH applets, OTP button actions, and local file
initialization. A partial, malformed or unreadable stored configuration latches a
fault that blocks credential operations until a validated reboot.

Forwarding is restricted to what the safe end implements: CTAP commands `0x01`
makeCredential, `0x02` getAssertion, `0x04` getInfo, `0x06` clientPIN, `0x08`
getNextAssertion, and the vendor exact query `0x50`. Credential management
(`0x0a`, `0x41`) is answered locally with `CTAP2_ERR_NO_CREDENTIALS`; everything
else (reset, config, largeBlobs, bio, other vendor commands) returns
`INVALID_COMMAND` without leaving the device.

## Pairing and provisioning over USB

Configuration uses the separate vendor HID collection (usage page `0xff31`). It
needs a controller key that is already paired with the device. Pairing itself
("按 BOOT 配对") requires only the physical BOOT gesture: release, hold at least one
second, release; up to four controller keys are stored in NVS, and removing one
needs the same gesture.

One pairing establishes trust in both directions. The device stores the
controller public key (local confirmation, signed configuration, and the relay
server identity below). On first boot the device also generates its own P-256
key in NVS (`remote_presence/device_key`), which never leaves the device; when
pairing completes the controller reads the public half (feature reports 20/21)
and saves it as `relay-devices/<serial><ext>`. Controller keys cannot be exported
or imported; each computer pairs on its own.

**设备设置** in the main window edits the mode, up to ten profiles (SSID, password,
safe-end host, port). **读取设备** (left of **写入设备**) reads the stored
configuration back from the device and replaces the local draft. SSIDs, hosts,
ports and the mode are returned normally; each non-empty password is returned as a
`PF2PW1` token sealed with a key derived from this device's own P-256 key and
bound to its USB serial. The controller can recognize and preserve the token but
cannot decrypt it. Writing the token back lets the device resolve the original
password. A token copied to another device fails to open.

On "写入设备" the controller signs the exact configuration bytes (P-256 over a
domain-separated context binding device serial, transaction, controller key ID
and a fresh device challenge), uploads it, and the device waits for the BOOT
gesture before writing NVS (`fido_relay/config_v1`), reading it back and
publishing its SHA-256. The UI reports success only when that digest matches its
own bytes. Setup expires after 120 seconds; any other authenticator operation
cancels it. A read cannot run while a write transaction is active.

The settings panel defaults to **写入成功后自动重启**: after verifying the saved
digest it sends an authenticated reboot, activating the new configuration.
**重启设备** also sends this command independently. Only a paired controller can
authorize it; an active authenticator request, pairing or configuration write
blocks it. Old firmware without this capability still requires unplug/replug.
The CLI equivalent is `pico-fido-cli --device SERIAL --device-reboot`.

The configuration (`PF2RCF03`) holds only the mode and profiles; it carries no
trust material. Relay mode can be written only after this computer has saved the
device's public key. Field limits are in the provisioning spec. Status reads and
the configuration read never return a plaintext Wi-Fi password; the configuration
read returns the non-secret fields and sealed password tokens. They do report the
last relay connection phase and Wi-Fi disconnect reason ("最近一次中转连接" in the
dialog).

The encrypted draft in `relay-settings/` is a recoverable copy, not device
authority. If it cannot be read (for example an older format), the settings
dialog offers to discard it; the device's stored settings are unaffected.

## Transport

Each request uses one TCP connection with TLS 1.2 (`ECDHE-ECDSA-AES128-GCM-SHA256`).
There is no CA, host-name check or clock: every service start issues a fresh
P-256 server key and certificate signed (ECDSA, SHA-256) by the controller key.
After the handshake the device accepts the server only if that certificate
signature verifies with one of its paired controller keys; the handshake itself
proves the server holds the certificate key. Certificate dates are nominal and
ignored.

The safe end then sends a 40-byte `PF2CHL01` challenge with a fresh nonce. The
device answers with a 122-byte `PF2REQ03` header (serial, random request ID,
per-boot random boot ID, CTAP length and an ECDSA signature by its device key)
and 1–1976 CTAP bytes. The signature covers the domain `pico-fido2 relay request
v1`, the challenge, serial, request ID, boot ID, length and the SHA-256 of the
CTAP bytes. The safe end verifies it with the saved device public key before
parsing the request, and re-checks that key while the request is pending. The
server answers with frames bound to the request ID and the SHA-256 of the
request: keepalives (processing / waiting for the user) and exactly one final
response. Version 4 requests also accept public discovery metadata frames (vault
identity, generation, PIN-configured hint); the protocol version is signed.
Version 3 firmware remains accepted without these frames. One connection carries
one operation, bounded to 90 seconds. This is a project budget, not a guarantee
that Windows gives every CTAP command 90 seconds. Once the
request may have been transmitted the device never retries it on another profile,
so an operation can be committed at the safe end even if its response is lost.

Wi-Fi starts with the last profile that obtained an IP address, remembered across
reboots. A configuration change invalidates that preference. Explicit association
failure advances to the next profile; an unassociated attempt is limited to eight
seconds. An associated network is retained while DHCP is pending.

Once connected, Wi-Fi stays on that profile even if DNS, TCP, TLS or the safe end
is unavailable. Background discovery retries the service without reconnecting
Wi-Fi. Only actual AP loss resumes Wi-Fi selection. Request cancellation closes
TCP, preserving the association; transmitted requests are never replayed.

Wi-Fi starts only in relay mode, with modem sleep and CPU scaling 80–160 MHz (no
USB light sleep). Relay sockets use TCP_NODELAY so short TLS records are not held
back. GetInfo itself uses no network.
With `LED_ACTIVITY_ONLY` the LED is off when idle and blinks red
(300/300 ms) while the safe end waits for a human approval.

GetInfo and device selection probes (makeCredential/getAssertion with an empty
`pinUvAuthParam`) are answered entirely on the USB device. Capabilities are fixed;
the PIN-configured hint comes from the last authenticated safe-end snapshot.
Only the public vault ID, PIN hint and its generation are persisted in NVS `fido_relay/info_v1`,
bound to the saved relay configuration digest. Changing configuration invalidates
the old hint on boot. Missing/corrupt hints initially report PIN not configured;
this grants no authorization, and an actual operation can require PIN/retry.
An authenticated response replaces the hint when the selected vault changes.
For the same vault, an older cached generation cannot replace a newer hint.

A background task prefetches GetInfo every five seconds with a five-second
budget. It never acquires a cloud lease. A foreground operation preempts this
prefetch; neither task can block local USB discovery. Cache flash writes happen
on the service task only when vault identity/PIN status changes. Probes report
"PIN set" (`0x31`) or "PIN not set" (`0x35`), never open a dialog, create a
credential, verify a PIN or change retries. Stale hints may require the client to
retry after learning the latest state; they cannot bypass server verification.

## Safe end

### Setup

**安全端管理** in the main window (or `Esp32KeyConfirm --safe-end`) opens the
safe-end manager. It needs no USB device or elevation and does not start a
listener by itself. Typical order:

1. Pair the device with this computer over USB ("生成本机密钥", "按 BOOT 配对").
   The safe end accepts only devices paired on this computer and OS user.
2. Create the vault: "初始化本机库" (local), or configure cloud storage and use
   "建立云端库" / "连接已有库" / "迁移到云端" (see Cloud storage).
3. In **设备设置**, choose "仅中转", add the Wi-Fi and safe-end host/port
   profiles, write with the BOOT gesture; automatic reboot activates the settings.
4. "打开凭证库", then "启动中转服务" (default `0.0.0.0:8443`; the bind address must be a
   numeric IP). CLI equivalent: `Esp32KeyConfirm --serve [ADDRESS PORT]`.

Firewall rules and trust stores are never changed; reachability (LAN/WAN/VPN) is
an installation task. The listener handles one connection at a time and holds the
vault until stopped. After starting the service, it remains enabled while the
manager is open and starts again on the next launch. Desktop lock, minimization
and idle time do not stop it. An OS session lock still cancels pending approval
dialogs. Listener/vault failures release the old session and retry every five
seconds, reopening and validating persisted state before serving again; credential
operations are never replayed. Recovery-code prompts still require an answer and
canceling one ends that start attempt. "停止中转服务", "停止并锁定" or exiting the
manager cancels retries, stops the listener and releases the vault. Manual stop
also disables automatic startup. A sleeping computer cannot serve requests until
the OS resumes it.

Nothing about the server identity is stored or renewed: the TLS key exists only
in memory for one service run. Changing the safe end's address needs only a new
profile in the device settings.

### Vault

Per credential the vault stores a random 32-byte ID, exact RP ID, user ID and
names, discoverability, signature counter and P-256 private key, plus per-device
relay PIN records. Older vaults are read without resetting credentials or PINs. Limits:
4096 credentials, 256 PIN records. Keys are sign/verify-checked on load. Writes are
flushed, atomically replaced and read back; an ambiguous write faults the vault
until reopened, and a file changed by someone else while held is refused.

The authenticator implements GetInfo (`FIDO_2_0`, clientPin, no built-in UV), ES256
makeCredential (packed attestation, all-zero AAGUID) and getAssertion. User
names and candidate counts are not disclosed in assertions, and accounts are never
enumerated over the relay; the full list is shown only in the safe-end manager.

### Approval

Each registration or login opens one dialog ("安全端 · 确认通行密钥请求") with the
device name/serial, exact RP ID, candidate accounts and a countdown. "拒绝" is the
default; with several accounts one must be selected. The decision is bound to that
single operation. Closing, expiry, USB cancel, disconnect during approval, revocation or session
lock rejects it. Exclusion-list matches and "no account" results also need
consent, so sites cannot silently probe. Enrollment and (for cloud vaults)
ownership are re-checked before and after the dialog and before the result.

Chrome's `appidExclude` compatibility check can send an HTTPS U2F AppID URL in
a silent `getAssertion` request before registration. Relay mode has no U2F
credentials and only creates credentials for DNS RP IDs. An unauthenticated
`up=false`, `uv=false` request with an explicit nonempty credential list in this
unsupported URL namespace therefore returns `NO_CREDENTIALS` without account
lookup or approval. It never maps a URL to its hostname. Normal RP queries,
PIN verification, registration and assertion approval retain their checks.

Windows may send a PIN-verified `getAssertion` preflight (`up=false`) followed by
the same assertion with `up=true` (or omitted). The preflight still asks for
consent and returns UP=0. Its approval covers exactly one subsequent formal
assertion, bound to the device boot/enrollment, PIN token, RP, challenge, complete
request except `up`, selected account and private key. The formal response has
UP=1. The latest vault is checked again; account/key changes require new consent.
Public GetInfo and normal per-command TLS teardown preserve this continuation;
other commands, failed response delivery and rejected assertions invalidate it.

Chrome also splits long registration exclusion lists into PIN-verified silent
assertions. The first approved negative result with an explicit nonempty credential
list opens a 15-second batch approval window. Further negative batches automatically
reuse that approval only for the same device boot/enrollment, PIN token and request
fingerprint. The fingerprint excludes only the changing credential list; RP,
challenge, exact options, extensions and PIN proof must match. Each batch reads the
latest vault; a matching account requires fresh account consent. Automatic batches
renew neither the approval window nor the PIN token deadline. The final registration
needs separate consent and consumes the token. Denial, cancellation, failed response
delivery and intervening commands other than GetInfo invalidate batch approval.

For `apple.com`, registration returns packed attestation with an `x5c` certificate,
as standalone mode does. A dedicated attestation key/certificate is created once
per vault and committed with the first approved Apple credential. It is encrypted,
backed up and migrated with the vault, independently of credential/TLS keys.
Other RPs retain self-attestation. This local certificate is not FIDO certification.
The first Apple registration upgrades storage to `PF2VLT03`; all controllers sharing
that vault must use this version or newer. Older programs reject the new format.

### ClientPIN

ClientPIN protocols 1 and 2 are implemented at the safe end (getRetries,
getKeyAgreement, setPIN, changePIN, getPinToken,
getPinUvAuthTokenUsingPinWithPermissions). Each device has its own relay PIN,
independent of the dormant local PIN on the hardware.

- Ordinary PIN verification and token issuance are automatic (no dialog); setPIN
  and changePIN need their own approval ("安全端 · 确认设备 PIN 请求"). A valid PIN
  grants UV, the operation approval grants UP; neither substitutes for the other.
- Eight attempts in total, each decrement committed before comparing; success
  resets the count. Three consecutive failures block PIN use until the device
  reboots or the service restarts; zero blocks it until reset. Since verification
  is automatic, wrong PINs consume retries without operator involvement.
- Tokens allow only makeCredential/getAssertion for one RP, last at most 30 s and
  are consumed by one formal request (also if it is then denied). A successful
  `up=false` preflight (including an approved negative exclusion-list result)
  preserves the token without extending its deadline;
  denied/canceled/failed assertions invalidate it. PIN state is bound to
  serial, per-boot boot ID and the device public key. The verifier is PBKDF2-HMAC-SHA256
  (600,000 iterations, random salt) of the PIN hash.
- Once a relay PIN exists, makeCredential requires a PIN token.

Recovery: stop the service, then "重置设备中转 PIN" or `--vault-reset-pin SERIAL`.
It clears only that device's relay PIN and retries; credentials stay. Issuing
tokens without a dialog is a deliberate product choice (CTAP 2.1 expects consent
on authenticators with a display); this implementation is not FIDO certified.

### Exact account query

Vendor command `0x50` with CBOR `{1: rpId, 2: userName}` (user name 1–64 UTF-8
bytes) asks whether exactly that RP and complete user name exist. Matching is
byte-exact, with no prefix or wildcard. A separate dialog
("安全端 · 确认账号查询") shows the submitted values; on approval the answer is only
`{1: true}` or `{1: false}`, and denial returns an error, never a result. From the
safe-end side, `--vault-query RP USER` answers locally; through relay hardware,
`--relay-query RP USER` sends the query over the device (exit code 0 yes, 2 no,
1 error).

## Backup and restore

"创建加密备份" (`--vault-export PATH`) writes a password-encrypted `.pf2bak`
snapshot of the open vault: all credentials, IDs, private keys, counters, vault
identity and per-device PIN records. "从备份恢复" (`--vault-import PATH`) restores
it into an uninitialized local vault (no data file and no `.lock`); it never
overwrites or merges. Passwords are 12–256 characters,
entered twice for export, and read only from the dialog or the controlling
terminal with echo off (never argv, environment or redirected stdin). Existing
backup files are never overwritten.

After a successful GUI export of a local vault, a separate confirmation offers
"保留本机库" (the default, also Escape/close) or "清空本机库". Clearing reopens
and decrypts the backup and requires its complete contents to match the current
vault, including identity, keys, counters and PIN state. It then removes only the
local vault and its lock marker; controller keys, paired devices, settings,
storage selection and the backup stay. The restore and initialization actions
become available again, so the same computer can switch between backup vaults.
There is no standalone clear action, no prompt after a failed export, and no
cloud-vault deletion. The CLI export remains non-destructive.

After a successful GUI export of a cloud vault, a separate confirmation offers
"保留绑定" (default, also Escape/close) or "解除本机绑定". Detach reopens and
decrypts the backup and compares it with the authenticated snapshot just exported.
It does not require the remote head to remain unchanged while the question is
visible: other clients may continue updating the cloud, which detach never writes.
After confirmation, the controller records a durable pending-detach selection,
closes the vault/helper (releasing its profile lock and cached secrets), deletes
only this namespace's local protected cloud profile, then records an unbound
selection. The profile contains the saved cloud authorization and coordinator
connection credentials. On restart, a confirmed interrupted detach is completed;
if cleanup cannot finish, storage stays unavailable rather than selecting a local
copy or reporting success. A failed/canceled export never offers detach.

The cloud vault, etcd state, other profiles, controller identity, device pairing,
backup and any retired migration source are preserved. Non-secret profile lock
markers remain to avoid splitting OS locks across inodes; generation guards remain
to prevent rollback if the same vault is reconnected. The unbound state enables
"初始化本机库", "从备份恢复", "配置云存储", "连接已有库" and "建立云端库".
Explicitly initializing or restoring local storage persists a local selection;
it never revives a retired migration source. If one remains, its encrypted file
and retired marker are preserved in `retired-local-<namespace>/` before creating
the new local vault. Restarting retains the selection. Reconnecting the old
cloud vault requires configuring its profile again.
This is a vault switch, not a cross-provider data migration or a computer wipe.
See [本机云端绑定与手动清理](local-cleanup.md) for the user workflow and manual
cleanup before returning a computer.

Storage ownership is retained through confirmation and deletion; canceling or
locking before deletion preserves the local vault. A durable `PF2CLR01` marker
records confirmed removal: on reopening, surviving vault data is retained and
its normal marker restored, or an unfinished marker cleanup is completed if the
data was already deleted. Ordinary missing or corrupt vault files are never
automatically reset.

Format `PF2BAK01` (also used for cloud snapshots): a 60-byte authenticated header
(magic, PBKDF2 iterations 600000, 32-byte salt, 12-byte nonce, plaintext length
≤ 8 MiB), then AES-256-GCM ciphertext and tag, keyed by PBKDF2-HMAC-SHA256.

A backup is a point-in-time copy. Restoring an old snapshot loses newer
credentials, PIN changes and counter increments, and running two copies at once
can make counters go backwards; keep only one active copy. The controller key,
paired device keys, device drafts and names are not part of the vault backup; a
replacement safe-end computer generates its own controller key and re-pairs.

## Cloud storage

A cloud vault is one encrypted `PF2BAK01` snapshot per commit, stored through an
rclone 1.75.2 backend (OneDrive, Google Drive or WebDAV) and coordinated by an
etcd v3 API cluster. Ordinary cloud sync is not a lock: the coordinator provides the
mutual exclusion and the authoritative "head" pointer. Without a reachable
coordinator, cloud vaults cannot be used.

`PicoFidoStorage` (beside the controller executable) runs on private inherited
pipes. It reuses the profile, provider HTTP pool and etcd client across short
transactions, exits after five minutes of foreground inactivity, and holds the
distributed mutex only during a transaction. It never
sees the recovery code or plaintext. Parent exit stops it (Windows kill-on-close
job, Linux parent-death signal, pipe EOF elsewhere). Its profile
`safe-end/cloud/<namespace><ext>` holds provider options/tokens, coordinator CA,
client certificate/key and the pinned cluster ID; DPAPI on Windows, otherwise
AES-256-GCM (`PF2CLS01`, namespace authenticated) under a separate keyring key
(service `PicoFido2Remote-storage`), failing closed without a keyring. The
namespace is a 32-character lower-case hex ID equal to the vault identity; all
computers sharing a vault use the same namespace, provider root and cluster.

### Locking and commits

Opening a cloud vault acquires an etcd mutex (15-second lease, kept alive), reads
and validates the snapshot, then releases it. Idle unlocked managers hold no
distributed lease. Real operations acquire a fresh snapshot; contention queues
with a bounded wait and respects cancellation. User approval releases the lease,
then reacquires and revalidates the latest PIN, selected account, exclusion list
and counter. Another client may commit during the dialog. A commit uploads the new ciphertext under a fresh
random 256-bit object name (`<root>/<namespace>/objects/`; WebDAV also sends
`If-None-Match: *`), checks the returned size/content checksum, then publishes the new head in an
etcd transaction that checks mutex ownership and the previous head. A paused
former owner cannot publish after a successor takes over.

When a provider returns a matching content checksum, full download/comparison
runs after lease release and does not delay the authentication response. Providers
without a checksum retain synchronous readback. Background reads are canceled
for foreground transactions, retry transient failures while idle, and verify the
exact uploaded object rather than a newer head. Queued work coalesces to the newest
complete snapshot and is best effort on shutdown/idle expiry. Confirmed corruption
faults the native session; it never rolls back counters. Subsequent uncached reads
always check the published SHA-256 and authenticated encryption.

Fail-closed rules: ambiguous writes, failed uploads/readback, validation failures
or loss of ownership during a transaction fault the vault. A failed/canceled
acquisition has made no mutation and a later request may try again. A possibly
delivered commit is never replayed: reopen to discover the authoritative result.
There is no local credential fallback, plaintext disk cache or merge. Each
transaction revalidates its snapshot and ownership before returning credentials
or account-query results. With a fresh lease, an exact head generation and
ciphertext SHA-256 match reuses the snapshot already authenticated in memory;
changed heads require a full download/decryption. This avoids two redundant
downloads for an unchanged vault around human approval. Provider directory
initialization is deferred until ciphertext IO, so a cache hit needs only the
coordinator. Unlocking still downloads the snapshot. Every counter commit still
uploads, reads back, verifies and publishes before returning the assertion.
Automatic management-list updates use the latest validated snapshot without an
extra cloud transaction; explicit refresh checks the authoritative head.
GetInfo, PIN-retry display hints and volatile key agreement use the last validated in-memory metadata without a cloud transaction.
PIN guesses, retry decrements, token issuance and credential commits always use
the current locked state. A crashed transaction holds its lease until expiry;
never delete lock keys by hand.

Time limits: helper requests have a 30 s base plus one second per 64 KiB of
payload, capped at 5 minutes; the native side allows the same scaling with a
6-minute cap per exchange.

Rollback guard: after every open and commit the safe end records, per namespace,
the newest authenticated vault generation it has seen
(`safe-end/cloud-<namespace>.generation`, `PF2HWM01 | namespace | LE64`). It
refuses to open a cloud head whose decrypted generation is older. This protects a
computer that has already seen a newer state against a restored older
coordinator/object pair; a computer opening the vault for the first time trusts
what it finds. The coordinator remains trusted against tampering and deletion.

### Configuring and selecting

"配置云存储" offers "新建 WebDAV 配置", "新建 OneDrive 配置", "新建 Google Drive 配置" and
"更新现有配置或重新登录". Every profile needs the coordinator URL, its CA, and this
computer's client certificate and key. Saving verifies the coordinator (TLS,
client-certificate auth, RBAC) and pins its cluster ID; it creates a new profile
only and never selects or opens a vault.

The operation selector and its inputs share one resizable form. Changing the
operation shows only the relevant fields; combined cloud/coordinator credential
updates are filled in together. Hidden fields are not required or submitted.
Inputs expand with the window, long forms scroll vertically, and non-secret text
and file paths have full-value tooltips. Validation errors stay in the form so
values can be corrected without another popup. Browser login/provider questions
and the final authorization-save review remain separate because they depend on
the provider's response.

- WebDAV: HTTPS URL, root, user, password (converted with rclone `obscure` inside
  the protected profile), optional private CA.
- OneDrive / Google Drive: the browser opens the provider's official login page;
  the helper listens on `127.0.0.1` with PKCE and a random state, for at most ten
  minutes. Google requires your own desktop-app Client ID and secret and scope
  `drive.file` (default) or `drive`; OneDrive can use rclone's app and a cloud
  region. Account passwords and tokens never reach the native application. A
  final "save_profile" review defaults to cancel.
- Maintenance renews OAuth authorization, replaces WebDAV credentials/CA, or
  replaces coordinator connection credentials (also together, e.g. when both have
  expired). Namespace, provider, root, drive, URL, user, scope/region and cluster
  ID stay bound. Before replacing the profile the helper takes the distributed
  lock and verifies the published snapshot with the new credentials.

A cloud vault has no chosen password. Creating or migrating one generates a
recovery code: 128 random bits as 26 Crockford base32 characters
(`XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`), shown once and typed back to confirm. Opening,
connecting from another computer and resuming need it; input ignores case, spaces
and dashes and reads I/L as 1 and O as 0. It is the `PF2BAK01` password, so a
leaked cloud object cannot be brute-forced offline; a lost code cannot be recovered.
The GUI combines an existing vault's ID and recovery code in one form. Creation
shows the generated recovery code and its confirmation input in the same form
(including the vault ID when needed). Recovery-code forms offer an unchecked
"在此电脑上记住恢复码（使用系统安全存储）" option. After successful verification,
the code is saved using Windows DPAPI or AES-GCM with a key in macOS Keychain /
Linux Secret Service; it never enters ordinary GUI preferences or helper profiles.
Opening the vault and starting the service (manually or automatically) first try
the remembered code and only prompt when needed. A cloud decryption authentication
failure clears the saved code and returns to manual input; network, coordinator
and protocol errors leave it intact. Canceling does not save an entered code.
Manual service start asks for the listen address/port first. Detaching the cloud
vault also removes its remembered code. Keep the offline recovery-code copy even
when remembering it on this computer.

Selection (`backend-v1`) is persistent. A new user starts with local storage.
"建立云端库" (`--storage-init-cloud NS`) creates a new cloud vault and
"连接已有库" (`--storage-open-cloud NS`) selects an existing one; both require that
no local vault exists and cloud configuration has been saved for the target namespace.
The GUI disables both actions until a saved cloud profile is available, and offers
only configured namespaces. Migration requires a profile matching the local vault
ID. Missing configuration is rejected before recording a pending operation.
`--storage-new-id` prints a fresh namespace for a new vault.
After selecting cloud there is no automatic switch back. A GUI backup followed
by confirmed "解除本机绑定" leaves an explicit unbound selection from which a
new local vault can be initialized, a backup can be restored, or a different
cloud vault can be selected, including when a retired local migration source
remains on disk.

### Migration and resume

"迁移到云端" (`--storage-migrate-cloud`) moves an existing local vault to a cloud
profile with the same namespace (the local vault ID, shown by the manager and
`--storage-status`), preserving credentials, counters and PIN records. Order:
validate the source and record a "moving" state with its digest and a fresh
32-byte creation token; reserve the namespace with that token (an initialized
target is never overwritten); retire the local copy (lock marker `PF2MOV01`, file
kept but unusable); upload and atomically publish the first head together with a
permanent `/committed` marker; save the cloud selection.

Initializing a new cloud vault uses the same token mechanism. If either is
interrupted, "恢复未完成操作" (`--storage-resume`) continues only the attempt
recorded on this computer: it opens the published vault if publication already
happened, or seeds it only if the coordinator proves nothing was ever committed.
A missing published head is never reseeded, and another computer's attempt cannot
be taken over.

### Coordinator deployment

Run a current stable etcd release (the client has been exercised against etcd
3.7.3) with HTTPS client listeners, `--client-cert-auth`, a dedicated client CA,
persistent storage and authentication enabled. Give each safe-end computer its
own client certificate (`clientAuth`, CN = etcd user) and a role granting only
`readwrite --prefix=true "/pico-fido2/v1/<namespace>/"`; clients need no admin role.
An optional private client portal (not part of this repository) provides a
shared-password page that issues a separate, namespace-scoped identity and
downloads the key, certificate, CA and setup instructions together. It requires
the vault ID copied from the controller's cloud configuration window; it never
generates a new namespace. Keep that window open until the files are downloaded.
Private keys are generated in memory and are not retained by the portal.
Restoring an etcd snapshot creates a new cluster ID, which existing profiles
reject; there is no in-place rebinding. Back up the coordinator only with all
writers stopped, together with the exact object referenced by each head. Uploaded
objects are never deleted by the application (no list/delete API); superseded
snapshots accumulate, so disable provider lifecycle rules and watch quota. Keep
periodic `.pf2bak` exports separately; provider tokens, controller pairing and
device configuration need their own recovery plan.

## Windows discovery timeout

If Edge reports `unknown device state (code:1,9,0x80070962)`, inspect
`Microsoft-Windows-WebAuthN/Operational` before changing the vault or its recovery
code. Windows gives discovery (CTAP `04` GetInfo) only about two seconds, which a
Wi-Fi/TLS/cloud round trip cannot reliably meet. GetInfo and selection probes
are therefore answered on the device from the cached hints described above; this
error with current firmware points at an older firmware or controller. Restart
an already-running controller after replacing its executable.

`pico-fido-cli --relay-status --device SERIAL` also prints the last network phase:
2/3 = Wi-Fi/address, 4 = DNS/TCP, 6 = TLS, 7 = sending, 8 = waiting for the safe
end, 9 = response received. Phase 9 does not by itself mean CTAP success.
`Wi-Fi reason 2` (`WIFI_REASON_AUTH_EXPIRE`) identifies a Wi-Fi authentication
timeout; check the current phase/readiness flags as well as the last disconnect
reason.

## Lost relay device

"撤销丢失设备" in the manager (or `--relay-enrollments`, `--relay-revoke SERIAL`)
deletes `relay-devices/<serial><ext>`. It needs no USB key or vault unlock and
works while the service runs: new requests from that device are rejected and
pending approvals canceled. Settings drafts cannot re-enable the device; pairing
it again with the BOOT gesture can.

Revocation is per safe-end computer and OS user (not synced through the vault);
revoke on every safe end that paired the device. It does not delete passkeys,
affect other devices, recall issued signatures or sessions, or erase dormant
local credentials on the lost hardware.

A lost safe-end computer is out of scope: the vault and its controller key go
with it, and a recovered setup reflashes or re-pairs the device.

## Security notes

- **Physical possession allows re-pairing.** Pairing a new controller requires
  only the BOOT gesture, not an existing controller. Whoever holds the key can
  pair their own controller, sign a `mode=local` configuration and reactivate the
  dormant local credentials. Those are then protected only by the local FIDO PIN,
  which does not help when the PIN can be coerced (scenario 4 in `new_design.md`).
  If you need that protection, do not keep credentials on the hardware before
  switching it to relay mode.
- **NVS is not encrypted by default.** With `ENABLE_ESP_EFUSE_KEYS=OFF` (the
  default) and without flash encryption, Wi-Fi passwords and the device private
  key are stored in plain NVS. A flash dump can impersonate the device. That
  alone does not release signatures: every operation still needs safe-end
  approval, and revoking the device on the safe end blocks the clone.
- A compromised safe end can approve anything; it holds the private keys.
- The device boot ID is not attestation of a power cycle; the persistent total of
  eight PIN attempts is what bounds guessing.
- A local lock does not coordinate computers. Never put a local vault in a sync
  folder as a substitute for cloud mode.
- No part of this design is FIDO certified or independently audited.

## Known limits and untested areas

- Live OneDrive/Google Drive accounts and third-party WebDAV servers (only
  self-hosted HTTPS WebDAV with etcd has been exercised).
- Deployed WAN/VPN operation.
- Power loss during the NVS configuration commit (simulated failures only).
- Apple Account enrollment/sign-in in relay mode (iPhone website registration and
  login in relay mode have worked).
- Several relay devices connected and used at the same time.
- Linux needs a udev rule for hidraw and a Qt DBus build for session-lock
  detection; the ESP network-worker host test is Windows-only.
