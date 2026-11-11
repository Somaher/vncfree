# Security

This customized Windows version is used in a LAN environment.

See the [2026-11-11 review](security-audit.md) for dependency updates, code fixes,
regression coverage, and remaining limitations.

What this program hands over, what protects it, and what does not. Written plainly
because a remote-desktop tool that is vague about this is not worth trusting.

## What the server actually gives away

**Everything the logged-in user can do.** Whoever gets past the password sees the
screen, moves the mouse, types, and reads and writes the clipboard, as that user. There
is no restricted mode, no per-permission model, and no audit trail beyond what the
server prints to its console. `VNC_VIEW_ONLY=1` is a *client-side* courtesy for the
person running the viewer; it is not a restriction the server enforces.

So the password is the whole boundary. Treat it as the password to that desktop,
because that is what it is.

## What protects it

| | |
|---|---|
| **In transit** | RSA-AES128 (RA2) authenticates and encrypts every record with AES-128-EAX after an RSA-2048 exchange. VeNCrypt TLS is also offered. |
| **Server identity** | Persistent RSA key (DPAPI protected) or TLS certificate. The viewer pins SHA-256 fingerprints separately per address and transport. |
| **The password** | Full password inside RA2; legacy VNC DES challenge-response inside TLS or plain TCP. |
| **Guessing** | Each failure from an address pushes back when that address may try again, up to 30 seconds. |

## What does not protect it

- **The first connection to a server is taken on trust.** There is no certificate
  authority for a program someone started on a desktop five minutes ago, so the first
  certificate cannot be checked against anything. After that a change is refused. If
  the first connection matters, compare the fingerprints both ends print.
- **VNC authentication is weak.** DES, and only the first **8 characters** of the
  password are used at all — everything after that is ignored, so a 20-character
  passphrase is an 8-character password. This limit applies to legacy VNC authentication, including inside TLS.
  RSA-AES128 checks the full UTF-8 password, up to 255 bytes. Inside TLS the exchange is not
  visible to the network; without TLS it is, and a captured exchange can be attacked
  offline at leisure.
- **A server that offers both encrypted and unencrypted connections can be pushed to
  the unencrypted one** by somebody in the middle, because the choice is the client's
  and the list is not signed. `VNC_TLS=ra2` requires RA2; `VNC_TLS=require` requires TLS at either end.
- **Nothing here defends the machine against the person who logged in.** If someone has
  the password they are that user.

## Do not put this on the internet

The dialog says so and this says so again. An 8-character DES password on a public port
guarding a whole desktop is not a defensible position, whatever the encryption is doing.
Tunnel it over SSH or a VPN, where the VNC password stops being the only thing between a
stranger and the machine.

## What has been hardened, and against what

These are the things the code does deliberately rather than by accident:

- **No length is trusted before the bytes behind it arrive.** Every length on this wire
  is a `u16` or `u32` chosen by the peer, and the obvious `vec![0; n]` hands four
  gigabytes of the process to anyone who sends four bytes saying so. On the client that
  was reachable *before any password was exchanged*, since a server states its refusal
  reason with one of these. Reads now grow as bytes actually turn up, so claiming four
  gigabytes costs the peer four gigabytes of sending.
- **Sizes that have a sane bound have one.** A screen (a claimed 65535x65535 desktop is
  a 17GB allocation), a pointer, a clipboard, and a line of text.
- **Every rectangle is checked against the framebuffer** before it is decoded into it,
  including a CopyRect's *source*, and every palette index and run length inside ZRLE
  and Tight. A malicious server should not be able to make the client write outside its
  own buffer or read a colour it was never sent.
- **The password comparison does not exit early**, so how long it takes says nothing
  about how much of the response was right.
- **Failed passwords are rate limited per source address**, and refused rather than
  delayed — holding the connection open on a timer would be a thread per attacker, which
  trades a defence against guessing for a cheaper way to exhaust the machine. One
  address guessing does not lock anyone else out.

## Where the risk is concentrated

`unsafe` is confined to Windows API calls: screen capture, input injection, dialogs,
DPAPI-protected settings, and Task Scheduler registration. It is driven by *local* values —
screen geometry, cursor bitmaps, window handles — not by anything off the wire. The
values a peer does control that reach it are a keysym, a pointer coordinate and a button
mask; the keysym goes through a total match with no indexing, and the other two are
scalars handed to Windows. There is no path from a network byte to a raw pointer.

`cargo audit` runs in CI against every push, so a published advisory against anything in
the dependency tree turns up there rather than in a user's hands.

## Reporting something

Open an issue. This is a small program with no users to coordinate with and nothing to
embargo, and a public issue gets it fixed faster than a private one.

RA2 follows the [RFB RSA-AES wire specification](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#rsa-aes-security-type).
It uses protocol-mandated SHA-1 for key derivation and transcript hashes and
RSA PKCS#1 v1.5 for encrypted randoms. Native Windows CNG performs RSA operations;
invalid RSA ciphertexts continue with a random secret and receive no padding-specific
error. This is a compatibility protocol, not a substitute for a modern VPN.
`VNC_STATE=off` disables persistent identities and viewer pinning for both transports.
The earlier security audit predates RA2; these additions have functional and independent
wire tests, but have not had a separate cryptographic security review.
