# Testing

```
cargo test
```

Everything below is about testing against something real, which is where the actual
bugs were.

## Autostart permissions and elevation

The opt-in Task Scheduler test creates, inspects, updates, and removes a uniquely
named temporary task:

```powershell
cargo test --lib autostart::tests::registers_interactive_headless_task_and_removes_it -- --ignored --exact
```

To check UAC, start the server without administrator rights and enable autostart on
a Windows account where task registration requires elevation. Accept the prompt and
verify that the task targets the original account, uses `--headless`, and runs with
normal user privileges. If a different administrator account approves the prompt,
the task must still target the original account. The helper should exit after the
task update; the original server continues at its existing privilege level.
Repeat with the prompt cancelled and confirm that an error is shown. Permission
errors in an already elevated process must report failure without another prompt.
If task registration succeeds without elevation, no prompt should appear.

## A real server to point at

Any RFB 3.8 server works. What this repo is developed against, via WSL:

```sh
sudo apt-get install -y tigervnc-standalone-server x11-xserver-utils
Xtigervnc :1 -geometry 800x600 -depth 24 -SecurityTypes None -rfbport 5900 &
DISPLAY=:1 xsetroot -solid "rgb:20/40/80"     # a known colour to verify against
```

Then `vncfree 127.0.0.1:5900 test.ppm` and check the PPM's pixels are `20 40 80`. A
red/blue channel swap shows up immediately as `80 40 20`, which a screenshot-only check
would miss.

Pass colours as `rgb:20/40/80`, **not** `#204080`. PowerShell strips `#` from
native-command arguments, and the resulting silent `xsetroot` failure looks exactly
like a broken decoder — a black screen.

## Checking an encoding is right

Grab the same screen twice with `VNC_ENCODING` set to `raw` and then to the encoding
under test, and compare the files. They must be byte-identical. Take a third Raw grab
to prove the screen was static, otherwise a difference might just be the clock ticking.

**A third grab is not enough on its own.** Anything that *blinks* aliases against it: a
text caret is on for the first and third grab and off for the second, so the screen
looks static and the encodings look broken. When they differ, look at *where* before
concluding anything. Differences confined to one small box — a 1x37 strip, say — are a
caret; a real encoder fault is spread across the picture or lands on tile boundaries.

That is how the client's ZRLE decoder and the server's ZRLE encoder were both checked:
identical output at 3840x2160, with the debug line confirming which encoding was
actually negotiated. Without that confirmation the comparison passes trivially when the
server quietly falls back to Raw.

### Tight, against TigerVNC

A decoder can look correct simply by never being handed the hard cases, so `VNC_DEBUG`
prints which form each Tight rectangle used. Driving TigerVNC through all of them is a
matter of changing what is on the screen:

```sh
DISPLAY=:1 xsetroot -solid 'rgb:20/40/80'                      # fill
DISPLAY=:1 xsetroot -mod 3 5 -fg 'rgb:ff/20/40' -bg 'rgb:10/80/c0'   # palette
convert -size 800x600 plasma:fractal /tmp/p.png
DISPLAY=:1 display -window root /tmp/p.png                     # basic copy
```

Each of those came back byte-identical to the same screen as Raw. JPEG needs one more
step: TigerVNC only sends it when the client asks for a lossy quality level, so
`VNC_QUALITY=5` is what makes that path reachable at all. It cannot be compared for
equality — it is lossy — so compare the mean channel error instead. Around 4 out of 255
on a plasma image is JPEG doing its job; a swapped red and blue, or a misframed blob,
is not a small number.

## Traps in the test harness itself

These each cost real time, and each one made correct code look broken:

- **Synthetic Windows input does not reach these windows.** `SendKeys`, and `SendInput`
  even when it reports every event accepted, reached neither the minifb session window
  nor the Win32 dialogs on the development machine. Test input by typing at it
  yourself, or by driving the RFB messages directly over a socket. An automated
  key-injection harness will look like a broken client when it is really a broken test.
- **Measure DPI-sensitive things from a DPI-aware process.** `GetCursorPos` in a
  DPI-unaware script reports logical coordinates, so a correctly injected pointer looks
  like it landed at half the right position. The authoritative reading came from
  querying the cursor *inside* the DPI-aware server, where the set and the read share a
  coordinate space.
- **An idle Xtigervnc can pin its pointer.** With no client connected it overrode
  `xdotool mousemove` entirely. Confirm that behaviour with vncfree *not* running before
  concluding the client mis-mapped a coordinate.
- **`cargo` writes progress to stderr.** In PowerShell 5.1, `2>&1` on a native command
  poisons `$?`, so a green build reports failure. Do not trust `$?` after redirecting.
- **A running `vncfree-server.exe` locks its own binary**, so `cargo build` cannot
  relink and the next test silently runs the *previous* build. This one cost an hour of
  investigating a certificate that would not persist, in code that was already correct
  and simply was not in the executable being run. Stop the server before building, and
  when a fix appears to do nothing at all, check the exe's timestamp before checking
  anything else.

## Verifying multi-monitor

`VNC_MONITOR=all` was verified on three real displays: a 4K primary at 200% scaling with
two 1080p screens at 100%, one of them placed to the *left* of the primary and therefore
at negative desktop coordinates. All three come across.

Two things nearly produced a false bug report:

- **Check the region a monitor actually occupies, not the strip it is in.** A screen
  placed lower than the primary has dead space above it, and sampling the whole strip
  reads as "all black, nothing captured". Read the monitor's own rectangle - Windows
  reports its origin and size, and the debug output prints them.
- **A black desktop is not a missing desktop.** The monitor here had black wallpaper, so
  "is it all one colour?" said missing when it was fine. The taskbar at the bottom of
  the crop is what settled it. Compare against a `CopyFromScreen` of the same virtual
  desktop taken from a DPI-aware process, which is an independent capture path.
