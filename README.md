# vncfree

This is my customized version of vncfree, adjusted to my liking for use in a LAN environment.

Free forever. No spyware, no bundled junk, no "free trial" nag screens, no telemetry,
no accounts, no subscription, no ad-gated download.

Two self-contained executables. Run them, close them, delete them. No installer, no
service. Optional autostart runs the server headless when you log in.

## Why

The state of free VNC software in 2026 is a disgrace.

RealVNC puts its **server** behind a subscription. UltraVNC makes you sit through an ad
to download it. TightVNC's Windows installer pushes a server on you when all you wanted
was a viewer. Meanwhile the "premium" options charge a recurring fee for software that
has not meaningfully changed since 2008.

This shouldn't be a market. RFB is a published protocol from 1998. The spec is a few
dozen pages, it is stable, and it is free to read. Remote desktop is a solved
engineering problem.

So here's the deal: vncfree is MIT licensed, the code lives on GitHub, and anyone can
build it, fork it, ship it or audit it. **If anyone tries to sell you this software,
they're scamming you. Walk away.**

Sister project to [bulkhead](https://github.com/sp00nznet/bulkhead),
[futureburn](https://github.com/sp00nznet/futureburn) and
[pstfree](https://github.com/sp00nznet/pstfree) — same attitude: find the Windows
payware, read the published spec it is hiding behind, give it away.
[Why](PHILOSOPHY.md).

### Prior art, credit where due

[TigerVNC](https://tigervnc.org) and [TightVNC](https://www.tightvnc.com) are genuinely
free and open source, and both are fine software — the complaint above is about how
TightVNC is *packaged*, not about its licence. If you need a mature, battle-tested
viewer today, use TigerVNC. vncfree exists because a viewer should be a single
executable you can drop on a machine and delete afterwards — and because the server is
the half everyone charges for, so that one is free here too.

## Use it

Double click either one and it asks what it needs.

- **`vncfree.exe`** — asks for an address, an optional username and a password.
- **`vncfree-server.exe`** — shows this machine's address on the local network and asks
  for a password. **Start server** stays greyed out until you type one.

Both are driveable from a script or a shortcut. Starting the server without arguments
always opens its dialog. **Load config** is enabled when a saved server config can be
decrypted and contains a password and valid listen address. Click it to fill in the
fields, then **Start server** to apply the saved settings and start sharing.
The server dialog also offers TLS mode, capture method, primary/all displays,
and **Autostart at login**. **Start server** applies
your edits and saves them encrypted. **Hide console after start** applies only to
that launch and is never saved. **Load config** fills all persistent controls.

**Autostart at login** creates a per-user Windows Task Scheduler task when you press
**Start server**. It runs this executable with `--headless` when you log in, using
your encrypted saved settings and normal user privileges. It runs only while you
are logged in, so it can share your desktop. No password is stored in the task.
Uncheck the option and press **Start server** to remove the task. Its name starts
with `vncfree-server-`; keep the executable in the same location, or re-enable
autostart after moving it. Task Scheduler is the source of truth for this checkbox;
**Load config** does not change it.
Task changes first use your current permissions. If Windows denies access and the
process is not already elevated, a UAC prompt requests administrator approval for
the task update only. The task still targets your original Windows login and uses
normal user privileges. Cancelling the prompt reports an error without starting
another server process.

```powershell
vncfree 192.168.1.50:5900              # connect
vncfree 192.168.1.50:5900 frame.ppm    # grab one frame headless and exit

$env:VNC_PASSWORD = 'up to 8 chars'
vncfree-server                          # open the server dialog
vncfree-server --password "secret" --headless  # no dialogs or console
```

Server arguments: `--password VALUE` (or `--password=VALUE`) overrides
`VNC_PASSWORD`. `--no-ui` (alias `--hide-ui`) disables all dialogs and fails if no
password is supplied. `--hide-console` detaches the server from its console without
hiding your terminal; `--headless` combines both. Use `--help` to list the options.
With `--headless` or `--no-ui`, if there is no supplied or saved password, the server
prints an error to stderr and exits with code 1 before detaching the console.
Command-line passwords can be visible in process listings; `VNC_PASSWORD` remains
available.

Close the client window to quit — Escape is forwarded to the remote machine, so it
can't also be the quit key.

### Settings

On Windows, settings are saved in `%APPDATA%\vncfree\server.cfg` and
`%APPDATA%\vncfree\client.cfg`. The entire file is encrypted with Windows DPAPI for
the current Windows account, including passwords. Client and server settings are
kept separate.

Precedence is **command-line arguments > environment variables > saved settings >
defaults**. In the server dialog, your edits override the initial environment values.
Settings supplied through `VNC_*` variables and passwords supplied on the
command line or in a dialog are saved automatically at startup. If no password is
supplied (including an empty value), the saved password is used. Server visibility
options (`--headless`, `--no-ui`, `--hide-console`, `VNC_NO_UI`, and
`VNC_HIDE_CONSOLE`) apply only to the current launch and are never saved. Visibility
flags in older config files are ignored and removed on the next save.
A launch without arguments always opens the dialog and
waits for **Load config** rather than automatically applying saved settings. For
scripted startup using saved settings, pass `--headless` or `--no-ui`.
`VNC_HIDE_CONSOLE=0` keeps the console attached unless `--hide-console` or `--headless`
is explicitly supplied.

To change settings, supply the new environment values or server arguments once;
subsequent launches use the saved values. For example:

```powershell
$env:VNC_BIND = '127.0.0.1:5900'
vncfree-server --password "secret" --headless
# Later, reuse the saved config without VNC_* variables:
vncfree-server --headless
```

The `.cfg` files are encrypted binary files, so edit settings through the server GUI,
arguments, or environment rather than a text editor. Delete the appropriate `.cfg` to reset its
saved settings. A damaged file or a file that cannot be decrypted produces an error;
it is preserved until you reset it. In the no-argument dialog, an invalid config
disables **Load config**; you can enter new settings and start to replace it.
Config files always live under `%APPDATA%`;
`VNC_STATE` only controls TLS state files.

| Variable | Effect |
|---|---|
| `VNC_PASSWORD` | Password. The server refuses to start without one. **Only the first 8 characters count** - that is VNC authentication, not a choice made here. |
| `VNC_ADDRESS` | Client only. Prefills the saved connection address in the dialog. An address argument overrides it. |
| `VNC_BIND` | Server only. Where to listen; default `0.0.0.0:5900`. |
| `VNC_NO_UI` | Server only. `1` disables dialogs; `0` restores them when a password is needed. |
| `VNC_HIDE_CONSOLE` | Server only. `1` detaches the console; `0` keeps it attached. |
| `VNC_VIEW_ONLY=1` | Watch without sending input. Also blocks clipboard writes. |
| `VNC_TLS` | `offer` (default), `require` or `off`. On the client, `require` refuses to connect to a server that will not encrypt. |
| `VNC_STATE` | Where the TLS state files below live. A path — `.` keeps them beside the executable — or `off` to disable TLS state persistence. |
| `VNC_ENCODING` | Client only. `raw`, `tight` or `zrle` to ask for exactly one. Answers "is it my decoder or the server?" |
| `VNC_QUALITY` | Client only, `0`–`9`. Lets a Tight server send lossy JPEG, which is much smaller on a slow link. Unset means lossless. |
| `VNC_DEBUG` | `1` prints the negotiated version, security types and clipboard traffic; `0` disables it. |
| `VNC_TIMING` | `1` prints each second's performance breakdown on the client or server; `0` disables it. |
| `VNC_CAPTURE=gdi` | Server only. Force `BitBlt` instead of Desktop Duplication. |
| `VNC_MONITOR=all` | Server only. Share every display as one screen, not just the primary. |
| `VNC_NO_PIPELINE=1` | Client only. Ask for each frame only after decoding the last. Slower; for servers that mishandle an early request. |
| `VNC_NO_CONTINUOUS=1` | Client only. Keep asking for each frame instead of letting the server send them unprompted. For servers that offer that and then mishandle it. |
| `VNC_NO_CURSOR=1` | Client only. Let the server paint the pointer into the picture instead of drawing it locally. Laggier, but it shows the remote machine's own pointer movement. |
| `VNC_SCROLL_DIVISOR` | Client only. Scroll delta per wheel click sent, default `12` (one plain mouse-wheel notch). A touchpad's driver picks its own units for the same swipe - lower this if scrolling feels slow, raise it if a light touch sends too much. |

### Files it writes

These files live in `%APPDATA%\vncfree` and are yours to delete. Optional autostart
also registers the per-user scheduled task described above. There is no installer
or Windows service.

| File | What it is |
|---|---|
| `server.cfg` | Server settings and password, encrypted with Windows DPAPI. |
| `client.cfg` | Windows client settings and password, encrypted with Windows DPAPI. |
| `server-cert` | The server's TLS certificate and its private key, made on first run. Kept so its fingerprint stays the same, because one that changed on every restart would be a fingerprint nobody could check anything against. |
| `known_hosts` | One line per address the **client** has connected to, with the certificate it saw. A plain text file. |

The client trusts the first certificate it sees from an address and **refuses to connect
if it ever changes**, which is what SSH does and for the same reason. It cannot make the
first connection safe — nothing can, without a certificate authority — but it does catch
someone who starts intercepting a connection you have used before.

If a server really was rebuilt, delete its line from `known_hosts` and connect again.
`VNC_STATE=off` disables TLS state files and certificate pinning. Encrypted `.cfg`
settings are still loaded and saved.

## What it does

| | |
|---|---|
| **Client** | Live window, keyboard, mouse, shared clipboard, automatic reconnect with backoff, view-only mode. **Ctrl-Shift-V** types the local clipboard at the remote machine, for servers that will not share one. **Ctrl-Shift-M** shows the next monitor, against vncfree-server |
| **Server** | Desktop Duplication capture with the cursor, keyboard and mouse injection, clipboard, mandatory password. An idle desktop costs about 20x less CPU than the `BitBlt` it falls back to |
| **Encodings** | Raw, CopyRect, ZRLE, and Tight for servers that speak nothing else. A full 3840x2160 screen is 33,177,616 bytes as Raw and 258,871 as ZRLE — 0.8%, a 128x reduction. Scrolling is sent as a move: one measured run shifted 3,974,784 pixels for 64 bytes |
| **Authentication** | VNC password authentication (DES challenge-response). |
| **Encryption** | TLS 1.3 over VeNCrypt, on by default, with the password exchanged inside it. `VNC_TLS=require` refuses to fall back |
| **Protocol checks** | TigerVNC and vncfree client/server sessions. |

Both ends speak RFB 3.3, 3.7 and 3.8 for compatibility with other VNC clients
and servers.

The server supports 8bpp and 32bpp true colour, including client-selected colour
maxima and shifts. Raw, ZRLE, and cursor shapes use the negotiated pixel format.

**The server will not start without a password.** An open VNC port hands the whole
desktop to anyone who can reach it, and defaulting to "no password" is exactly the
decision that makes remote-access software dangerous. It offers only VNC
authentication, so there is no unauthenticated path at all.

## Known limits

- **The first connection to a server is taken on trust.** After that the certificate is
  remembered and a change is refused, but there is no certificate authority for a
  program someone started on a desktop five minutes ago, so the first one cannot be
  checked against anything. Compare the fingerprints both ends print if that first
  connection matters. A server that offers both encrypted and unencrypted connections
  can also be pushed to the unencrypted one by someone in the middle — `VNC_TLS=require`
  at either end removes that choice. **Still don't port-forward this to the internet**:
  tunnel over SSH or a VPN.
- **Encryption needs both ends to be vncfree.** VeNCrypt's other TLS modes use
  anonymous Diffie-Hellman, which cannot detect anyone in the middle at all and which
  no current TLS library implements; vncfree speaks the X509 form instead. Against
  another client or server the connection falls back to plain VNC auth, which is DES
  and weak by modern standards.
- **Tight is decode-only.** The client reads it, so servers that offer nothing better
  are no longer stuck on Raw; the server still sends ZRLE, which is a comparable size
  and lossless. Encoding Tight well means a JPEG *encoder*, which is a lot of weight
  for a squeeze on top of what is already there.
- **The pointer is drawn locally, so it does not follow the remote machine's own
  mouse.** That is the trade that makes it move without waiting for the network: the
  client draws the pointer at *your* mouse position. If somebody is sitting at the
  other machine moving its mouse, you will not see their pointer move.
  `VNC_NO_CURSOR=1` goes back to the server painting it in, which is laggy but shows
  everything.
- The server's CopyRect covers vertical scrolling but not a window dragged sideways.
  Compatibility is unaffected — that costs bytes, not connections.
- The server shares the primary monitor by default; `VNC_MONITOR=all` shares every
  display as one screen. Sharing more than one falls back to `BitBlt`, because Desktop
  Duplication works per output — so it costs more CPU than a single-monitor session.
  Verified on three real displays, including one to the *left* of the primary and so at
  negative coordinates, and with mixed scaling: a 4K primary at 200% beside two 1080p
  screens at 100%. Any gap between monitors comes across as black, because on the
  desktop it genuinely is nothing.
- A client can also switch monitors mid-session: vncfree-server sends its list of
  monitors and shares whichever one the client picks. RFB has no standard way to do
  this, so it is a vncfree extension — two private pseudo-encodings that any other
  server or client ignores. In the Windows viewer **Ctrl-Shift-M** steps through them
  (1, 2 ... then all, then 1 again; the window title says which), and works in
  view-only mode too.
- The server follows a resolution change, but a client that did not ask for
  DesktopSize cannot be told, so that session ends and has to reconnect — vncfree's own
  client reconnects by itself.
- **Ctrl and Alt shortcuts assume a US layout.** Ordinary typing follows whatever
  layout Windows is set to, including AltGr and dead keys, but a shortcut is sent by
  physical key position — Ctrl-C is the key where a US keyboard has C. That is usually
  what people want from a shortcut and is what most viewers do.
- Holding a character key sends repeats rather than one long press, because Windows
  reports the repeats. Fine for typing, not for holding a key down in a game.
- **To control an admin window, run the server as administrator.** Task Manager, Event
  Viewer, regedit, Services and anything else started with "Run as administrator" ignore
  input from a program that is not elevated itself — Windows drops it without saying so,
  so the screen keeps updating while every click and key goes nowhere. Right-click
  `vncfree-server.exe` and choose **Run as administrator** when you need those.
  UAC prompts and the Ctrl-Alt-Del screen are out of reach either way: those need a
  service running as SYSTEM, which this deliberately is not.

## Documentation

- **[docs/security.md](docs/security.md)** — what the server hands over, what protects
  it, what does not, and what has been hardened against what.
- **[docs/design.md](docs/design.md)** — how it is put together, why each dependency is
  there, and the traps that cost real time.
- **[docs/testing.md](docs/testing.md)** — standing up a real server to test against,
  and the harness mistakes that make correct code look broken.

## Contributors

- **[tariqhamid](https://github.com/tariqhamid)** — opening the session window at a
  size that fits the screen, including large framebuffers; and touchpad scrolling
  that follows the swipe
  ([#1](https://github.com/sp00nznet/vncfree/pull/1)).

## Building

```
cargo build --release
```

Produces `target/release/vncfree.exe` and `target/release/vncfree-server.exe`, with no
runtime to install.

Build this customized version from this checkout to include the LAN-specific changes.

## The sister projects

| | |
|---|---|
| [bulkhead](https://github.com/sp00nznet/bulkhead) | Block-level backup, recovery and certified secure erase for Windows. |
| [futureburn](https://github.com/sp00nznet/futureburn) | CD, DVD and Blu-ray burning, ripping and image mounting. |
| [pstfree](https://github.com/sp00nznet/pstfree) | Read, export and repair Outlook PST/OST files without Outlook. |

Same method every time: read the published spec, call the OS API that is
already there, ship one executable, MIT. Why that is worth doing at all is
written down in **[PHILOSOPHY.md](PHILOSOPHY.md)**.

## License

MIT. See [LICENSE](LICENSE). Free forever, for everyone. The whole point is that nobody
pays for this.
