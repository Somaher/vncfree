# Security review - 2026-11-11

Scope: version 0.6.0, Windows x64. This review covered locked dependencies, network
message parsing, authentication, connection lifetime, saved settings, the elevation
helper, and CI permissions. It combined source review with targeted regressions;
it was not an independent penetration test or exhaustive fuzzing campaign.

## Dependencies

RustSec reported five advisory matches in the original lockfile. The affected
packages were updated without changing their major versions:

| Package | Before | After | Advisories |
|---|---|---|---|
| `rustls` | 0.23.45 | 0.23.46 | [0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) |
| `rustls-webpki` | 0.103.15 | 0.103.16 | [0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) |

These are version matches, not evidence of exploitation in this application. Some
conditions, including ECH, Brotli certificate decompression, and custom session-cache
logging, are not enabled here. Updating removes the affected dependency versions.

After updating, `cargo audit` reported **zero vulnerability matches and no yanked
versions** against advisory database commit
`28d73fc95e5972af3403225a217def57dcaba3c4`.

The maintenance notice [RUSTSEC-2024-0384](https://rustsec.org/advisories/RUSTSEC-2024-0384.html)
for `instant` remains in the cross-platform lockfile. It is not in the Windows x64
dependency graph, as checked with `cargo tree --target x86_64-pc-windows-msvc -i instant`.
The warning is not suppressed.

## Code findings fixed

| Finding | Impact | Change |
|---|---|---|
| Unlimited unauthenticated connections and no handshake deadline | Remote thread/socket exhaustion | Limit connections to 16. A 15-second watchdog closes stalled or slow-drip handshakes; per-handle 15-second I/O timeouts also bound pending Windows reads/writes, which may outlive shutdown on a duplicate handle. |
| Unbounded zlib output and peer-selected ZRLE input size | A malicious server could exhaust client memory | Bound decoded output and compressed input by the rectangle's maximum representation; reject trailing decoded data. |
| JPEG pixels decoded before dimensions were checked | A tiny rectangle could advertise a much larger image allocation | Parse metadata and verify dimensions/pixel format before decoding, with a decoding buffer limit. |
| Password failure count forgotten when its penalty expired | Serial guesses always restarted at the shortest delay | Retain counts for ten minutes, bound the address table to 4096 entries, and saturate counters. |
| Oversized text and clipboard messages drained before rejection | A peer could keep a reader occupied with an arbitrary body | Reject oversized lengths immediately from the header. |
| Unbounded legacy DH key sizes and ZRLE run descriptions | Peer-controlled expensive computation or excessive parsing | Bound DH keys to 64-512 bytes and runs to the maximum tile size. |

Additional hardening replaces the handwritten password-response comparison with
`subtle::ConstantTimeEq`, bounds session writes to 30 seconds, and closes sockets and
joins the frame worker when the connection reader exits. Successful handshakes clear
read timeouts on both live transport handles so idle authenticated sessions work.

## CI hardening

- Pin third-party actions to immutable official commit hashes.
- Give build and audit jobs read-only repository permissions.
- Do not persist checkout credentials in the local Git configuration.
- Grant release-write access only to the version-tag release job, which downloads
  completed Windows build artifacts and requires both build and audit success.
- Pin the dependency-audit tool version while continuing to fetch current advisories.

## Regression coverage and remaining boundaries

Validation completed: 120 active tests passed, Clippy with warnings denied passed,
formatting passed, and both Windows x64 release binaries built successfully. The
opt-in test that creates a scheduled task was not rerun during this review.
The CI YAML, action pins, token permissions, and release dependency gates were also
checked locally; the modified workflow has not yet run on GitHub Actions.

Regressions cover decompression expansion, oversized ZRLE lengths and runs, mismatched
JPEG dimensions, oversized DH keys, header-only rejection, handshake timeout and
cancellation and slow-drip peers on Windows, retained password backoff, bounded failure records, and
connection admission/reuse against the real server.

VNC DES authentication still uses only eight password bytes. Compatibility modes
still allow plaintext or encryption downgrade; use `VNC_TLS=require` when encryption
must be enforced. Certificate pinning still trusts the first connection. DPAPI does
not protect secrets from software already running as the same Windows user. These
protocol and trust boundaries are described in [security.md](security.md).

Interactive UAC consent, cancellation, and approval by a different administrator
remain manual checks described in [testing.md](testing.md#autostart-permissions-and-elevation).

## Subsequent RSA-AES128 implementation

RA2 was added after the review above. It uses Windows CNG RSA, RustCrypto EAX,
DPAPI protection of the persistent server identity, separate RSA host-key pins,
full-password comparison, bounded RSA parameters and authenticated session records.
Its added dependencies were checked against the same advisory database with no
vulnerability matches (`cargo audit --no-fetch --no-yanked`). Functional validation
includes an independent PyCryptodome peer in both directions. This does not constitute
an independent cryptographic review of the protocol or implementation.
