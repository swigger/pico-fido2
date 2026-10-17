# Private storage helper protocol PF2STO01

Protocol between the native controller (`tools/native-controller/relay_cloud.cpp`)
and its owned storage child `PicoFidoStorage` (`tools/relay-storage`, `pipe.go`,
`setup.go`, `enrollment.go`, `maintenance.go`). Overview: [relay.md](relay.md).

## Process and transport

The parent starts the helper from the fixed absolute path beside its own
executable (`PicoFidoStorage.exe` / `PicoFidoStorage`), with the helper's directory
as working directory. Arguments carry only the mode, the namespace and optionally
an explicit absolute profile path. Credentials, tokens and vault passwords never
appear in argv or the environment. There is no TCP/HTTP IPC endpoint.

- Windows: two random local named pipes opened by the parent before launch,
  rejecting remote clients, with a protected DACL for the current user and SYSTEM.
  Only stdin, stdout and a NUL stderr are inherited (explicit handle list). The
  child is assigned atomically at creation to a private kill-on-close job, so
  parent death stops it. Parent IO is overlapped with 25 ms cancellation polling;
  pending IO is canceled and completed before buffers are freed.
- Linux/macOS: two anonymous close-on-exec pipes dup'ed to fd 0/1, `/dev/null` on
  fd 2, all other descriptors closed (`closefrom` on glibc ≥ 2.34,
  `POSIX_SPAWN_CLOEXEC_DEFAULT` on macOS), spawned with `posix_spawn` in its own
  process group. Parent IO is non-blocking with 25 ms `poll`. Teardown closes the
  pipes, waits up to one second, then kills the process group. On Linux the helper
  also sets `PR_SET_PDEATHSIG` and exits if it was already reparented; elsewhere
  it relies on pipe EOF.

The helper refuses to run unless stdin and stdout are pipes (Windows pipe handles;
FIFO or socket on Unix). Parent EOF cancels all in-flight provider work. A clean
close releases the distributed mutex; a crash leaves it until the etcd lease
expires.

Vault helpers retain the profile and network clients across transactions and
exit successfully after five minutes without a foreground request, with no lease
held. Background audits do not extend this idle lifetime. Release ends the lease;
Close ends the child. The parent uses Wake before reusing an idle child. Only a
clean exit at this boundary permits restarting before Open; no commit is retried.
Exit status 2 means confirmed background corruption and faults the native vault.

Deadlines: the parent allows each exchange its base timeout (default 60 s) plus
one second per 64 KiB of payload (an Open assumes the maximum payload), capped at
6 minutes; Close gets 5 seconds; enrollment and maintenance flows have 10 minutes
in total. Inside the helper, lock acquisition has 30 s, each provider transfer
30 s plus one second per 64 KiB (capped at 5 minutes), and lease revocation on
close 3 s.

## Framing

All integers are little-endian. Each request has a 24-byte header:

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII `PF2STO01` |
| 8 | 4 | Payload byte length |
| 12 | 1 | Operation 1–13 (which ones are valid depends on the child mode) |
| 13 | 3 | Reserved; all zero |
| 16 | 8 | Sequence, exactly 1 then incrementing |

Maximum payload is `8*1024*1024 + 85` for vault sessions and 256 KiB for setup,
enrollment and maintenance children (checked before allocation). Unknown
operations, oversized frames, nonzero reserved bytes, skipped/repeated sequence,
truncated input and parent EOF terminate the session. Responses use the same
sequence and operation OR `0x80`. The first response payload byte is status: `0`
success, `1` failure, `2` confirmed background corruption. Failure has no further bytes and ends the session; upstream
OAuth, HTTP or file error messages are never echoed. The parent marks its vault
faulted on any malformed, error or missing response and never retries a possibly
delivered commit.

## Vault session: `--pipe NAMESPACE [PROFILE_PATH]`

| Operation | Request payload | Successful response after status byte |
| --- | --- | --- |
| 1 Open | Mode byte: 0 existing, 1 initialize, 2 explicit resume; modes 1/2 may append a 32-byte creation token (required for 2, forbidden for 0) | Generation LE64; populated state also includes the encrypted snapshot |
| 2 Read | Empty | Generation LE64 followed by encrypted snapshot |
| 3 Check | Empty | Empty |
| 4 Commit | Expected generation LE64 followed by encrypted snapshot (at least 112 bytes, `PF2BAK01`) | New generation LE64 (expected + 1) |
| 5 Close | Empty | Empty, after resources/ownership have been released |
| 11 OpenCached | Previously authenticated head generation LE64 followed by ciphertext SHA-256 (32 bytes) | Generation LE64; encrypted snapshot on a cache miss, no snapshot only on an exact generation/hash match |
| 12 Release | Empty, active transaction required | Empty after the lease is released; keep network clients idle |
| 13 Wake | Empty, no active transaction | Empty after pausing background IO and checking audit health |

Operations 6–10 are refused by vault sessions.

Open or OpenCached starts a transaction; another Open is allowed only after
Release. Sequence numbers continue across transactions. OpenCached opens
only an existing namespace, reacquires its distributed lease and validates the
current head/ownership. It never uses a cache when the coordinator is unavailable.
The parent accepts an empty snapshot only for the requested generation and keeps
its rollback guard. A changed head downloads and authenticates the full snapshot.
Use matching parent/helper versions; older helpers reject Release/Wake.

An initialize open returns
generation zero and no snapshot; the parent then creates its initial encrypted
vault and commits with expected generation zero. Ordinary open never initializes
missing data. Generations describe the cloud head and are separate from the
encrypted vault's own revision (which the native rollback guard tracks).

Creation tokens: the native selector persists a fresh token before initialization
or migration and always supplies it with mode 1. Its hash is bound in the
coordinator's `v3:` initialized anchor. Mode 2 accepts only the same creation
attempt: it returns the existing authenticated snapshot when one was published,
or generation zero only when the permanent `/committed` marker proves nothing was
ever published. The first commit atomically writes both head and `/committed = 1`.
A missing published head cannot be reseeded. Mode 2 can also reserve a still-absent
namespace after a crash before helper launch. Tokenless mode 1 cannot later resume
a headless reservation. Interrupted initialization leaves a permanent etcd marker
that is never reset automatically. The token contains no vault password or key.

The helper treats snapshots as opaque `PF2BAK01` bytes and never receives the vault
password. It checks remote ownership before and after reads. A new upload's
server-reported size and available content checksum are checked before publishing
the head. SHA-256 is preferred; OneDrive QuickXorHash detects accidental corruption
but does not replace authenticated vault reads. Missing checksums fall back to
synchronous full readback. A mismatching receipt never publishes a head.
Receipt-verified objects are queued for full SHA-256 verification after release,
outside the distributed lock and foreground response. New foreground work cancels
the audit read first without poisoning the shared transport. Queued snapshots
coalesce to the newest complete vault; each running audit uses its own immutable
object name/hash, never the latest head. Network failures retain pending work and
retry while idle; completed mismatches stop the session without rolling back a
counter or head. Audits are best effort on shutdown/idle expiry; later uncached
reads still verify SHA-256 and the native authenticated encryption. The parent must
decrypt, validate all keys and schema, and bind the vault identity to the
namespace before using any credential. `Check` is required before approvals and
read-only results; a local timer or an earlier successful check is not authority.
The native vault acquires a separate lease for each transaction and releases
it before waiting for operator approval, retaining the helper for up to five idle
minutes. After approval it reacquires, validates
the newest snapshot and rechecks PIN/account/counter decisions before acting.
The helper's mutex acquisition queues up to its deadline (and parent cancellation)
instead of failing immediately on contention. Commit is never automatically
replayed. Close does not reverse committed data. Public discovery/PIN-status hints
are served from the last validated metadata without calling this pipe; they grant
neither user verification nor credential access.

## Profile setup: `--setup-pipe NAMESPACE [PROFILE_PATH]`

A one-shot child. It accepts only operation 6, sequence 1, with a JSON payload of
1 byte–256 KiB: `{"profile": <CloudProfile>, "webdav_password": "..."}`. Unknown
fields, trailing JSON, namespace/version mismatch, mixed password/bearer
authentication and oversized frames fail closed. A raw WebDAV password (≤ 4096
bytes) is converted with upstream rclone `obscure`, then the complete profile is
written protected (DPAPI on Windows, keyring-sealed `PF2CLS01` elsewhere). A blank
cluster ID is filled in only after successful TLS, client-certificate and RBAC
verification; a supplied ID must match. Setup creates a new profile only; it never
selects or opens a vault and never overwrites an existing profile. Success is an
empty payload after status 0. Further input or EOF cancels the work.

## Enrollment: `--enroll-pipe NAMESPACE [PROFILE_PATH]`

OAuth onboarding for OneDrive or Google Drive, bounded to ten minutes. It never
opens a vault.

| Operation | Request payload | Successful response after status byte |
| --- | --- | --- |
| 7 Start | Strict `{"profile": <CloudProfile>}` JSON; new-profile enrollment fields only | Typed step |
| 8 Answer | UTF-8 answer, at most 8192 bytes, no NUL | Next typed step |
| 9 Poll | Empty, only while awaiting the browser | Waiting or next typed step |
| 5 Close | Empty | Empty after enrollment cancellation |

Start is accepted once. Before starting OAuth the helper verifies and pins the
coordinator, rejects existing profile/lock files, and validates provider inputs.
Drive requires client_id/client_secret and scope `drive.file` or `drive`; OneDrive
accepts optional application credentials and an upstream region. No token,
service-account, custom endpoint or custom OAuth CA input is accepted. The browser
URL must be an HTTPS URL on an allowlisted provider host (the parent re-checks:
`accounts.google.com`, `login.microsoftonline.com`, `login.microsoftonline.us`,
`login.microsoftonline.de`, `login.chinacloudapi.cn`).
The callback listens only on `127.0.0.1` at a fresh port; PKCE S256, a random state
and a single accepted terminal callback bind the result. Code exchange has a
20-second budget, verified TLS and no redirect following.

Typed steps begin with one kind byte: 0 Done (no further bytes), 1 Browser (one
string URL), 2 Waiting (no further bytes), 3 Question or 4 Review. Strings are
LE32 length plus strict UTF-8, at most 8192 bytes, no NUL. A Question/Review holds
name, help and default strings; a flags byte (required=1, exclusive=2, secret=4;
other bits forbidden); then a LE16 count up to 128 and that many value/help string
pairs. A step is at most 256 KiB. Answers to exclusive questions must match a
listed value. Review is named `save_profile`, defaults to cancel and accepts `save`.
After Browser, the parent opens the system browser (outside the helper's job or
process group) and polls; it sends no Answer for that step. Done is returned only
after the protected profile exists. Tokens never appear in typed steps. No profile
is written before review, and a profile created concurrently is never overwritten.
An interrupted durable save may exist without an acknowledged Done; do not delete
it or retry blindly.

## Maintenance: `--maintain-pipe NAMESPACE [PROFILE_PATH]`

Updates an existing protected profile through the same ten-minute typed flow. The
first operation must be **10 Maintain**, sequence 1, with strict JSON of
1 byte–256 KiB; then 8 Answer, 9 Poll and 5 Close follow the enrollment rules.
Operation 7 is refused here, and enrollment refuses operation 10.

The payload is a patch, not a replacement profile:

| Field | Meaning |
| --- | --- |
| `action` | Required: `oauth`, `webdav` or `coordinator` |
| `client_id`, `client_secret` | Optional application credentials for `oauth`; omission keeps the existing value, but a changed Client ID clears the previous secret |
| `secret` | Required nonempty new password/bearer token for `webdav`; authentication mode and username are preserved |
| `provider_ca_file` | Optional WebDAV CA path; omission keeps it, empty selects system trust |
| `coordinator` | Complete new connection object: `endpoints`, `ca_pem`, `client_cert_pem`, `client_key_pem`, optional `cluster_id`; required for `coordinator`, also allowed with either credential action |

Unknown fields, trailing JSON, inappropriate combinations and strings over 4096
UTF-8 bytes or containing NUL are refused. A supplied cluster ID must equal the
saved one. Namespace, provider, root, drive ID/type, URL, username, region, scope
and all other location/binding options cannot change. Only decoding the old
profile may skip certificate validity or a missing old provider CA file; every new
connection uses verified TLS, RBAC and the pinned cluster identity.

The helper keeps the local profile lock through login and review. OAuth discards
the old in-memory token to require a fresh browser grant; drive discovery must
keep the saved binding. Review defaults to cancel. On `save` the helper acquires
the namespace's distributed mutex in a read-only inspection mode (it cannot
commit, initialize, upgrade a legacy anchor, repair a missing head or upload),
reads and verifies any published snapshot against the head with the new
credentials, stages token refreshes in memory, then atomically replaces the
profile after re-checking the original profile's ciphertext hash, with ownership
checked before and after. Done acknowledges replacement only after these checks;
a failure after a possibly durable replacement is not rolled back. Never-published
namespaces can be updated but give no proof of provider access. Maintenance never
decrypts a vault or changes the backend selection.
