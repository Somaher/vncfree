"""Independent RA2 wire test. Requires PyCryptodome; pass the server exe path.

Uses temporary APPDATA and loopback; never registers autostart or writes clipboard.
"""
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA


def exact(s, n):
    data = bytearray()
    while len(data) < n:
        part = s.recv(n - len(data))
        if not part:
            raise EOFError("peer closed")
        data.extend(part)
    return bytes(data)


class Records:
    def __init__(self, s, receive, send):
        self.s, self.receive, self.send = s, receive, send
        self.incoming = self.outgoing = 0
        self.buffer = b""

    def write(self, data, tamper=False):
        header = struct.pack(">H", len(data))
        c = AES.new(self.send, AES.MODE_EAX, nonce=self.outgoing.to_bytes(16, "little"))
        c.update(header)
        encrypted, tag = c.encrypt_and_digest(data)
        if tamper:
            tag = bytes([tag[0] ^ 1]) + tag[1:]
        self.s.sendall(header + encrypted + tag)
        self.outgoing += 1

    def read(self, n):
        while len(self.buffer) < n:
            header = exact(self.s, 2)
            size = struct.unpack(">H", header)[0]
            encrypted, tag = exact(self.s, size), exact(self.s, 16)
            c = AES.new(self.receive, AES.MODE_EAX, nonce=self.incoming.to_bytes(16, "little"))
            c.update(header)
            self.buffer += c.decrypt_and_verify(encrypted, tag)
            self.incoming += 1
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


@contextmanager
def server(exe, appdata, mode="ra2"):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith("VNC_")}
    env.update(APPDATA=appdata, VNC_BIND=f"127.0.0.1:{port}", VNC_TLS=mode, VNC_CAPTURE="gdi")
    child = subprocess.Popen([str(exe), "--no-ui", "--password", "abcdefgh-full-password"],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            if child.poll() is not None:
                raise AssertionError(child.stderr.read().decode(errors="replace"))
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=10)
                break
            except ConnectionRefusedError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.025)
        with s:
            yield s
    finally:
        child.terminate()
        child.communicate(timeout=10)


def negotiate(s, password):
    assert exact(s, 12) == b"RFB 003.008\n"
    s.sendall(b"RFB 003.008\n")
    offers = exact(s, exact(s, 1)[0])
    assert offers == bytes([5]), offers
    s.sendall(bytes([5]))
    bits_bytes = exact(s, 4)
    bits = struct.unpack(">I", bits_bytes)[0]
    assert bits == 2048
    size = bits // 8
    modulus, exponent = exact(s, size), exact(s, size)
    public = bits_bytes + modulus + exponent
    remote = RSA.construct((int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")))
    ours = RSA.generate(2048)
    own_public = bits_bytes + ours.n.to_bytes(size, "big") + ours.e.to_bytes(size, "big")
    s.sendall(own_public)
    random = os.urandom(16)
    encrypted = PKCS1_v1_5.new(remote).encrypt(random)
    s.sendall(struct.pack(">H", size) + encrypted)
    assert struct.unpack(">H", exact(s, 2))[0] == size
    theirs = PKCS1_v1_5.new(ours).decrypt(exact(s, size), b"invalid")
    assert len(theirs) == 16
    r = Records(s, hashlib.sha1(random + theirs).digest()[:16],
                hashlib.sha1(theirs + random).digest()[:16])
    r.write(hashlib.sha1(own_public + public).digest())
    assert r.read(20) == hashlib.sha1(public + own_public).digest()
    assert r.read(1) == bytes([2])
    p = password.encode()
    r.write(bytes([0, len(p)]) + p)
    return r, public


def viewer_test(exe, appdata):
    viewer = exe.with_name("vncfree.exe")
    identity = RSA.generate(2048)
    public = struct.pack(">I", 2048) + identity.n.to_bytes(256, "big") + identity.e.to_bytes(256, "big")
    env = {k: v for k, v in os.environ.items() if not k.startswith("VNC_")}
    env.update(APPDATA=appdata, VNC_TLS="ra2", VNC_PASSWORD="abcdefgh-full-password", VNC_ENCODING="raw")
    image = Path(appdata, "frame.ppm")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(10)
        address = "127.0.0.1:%d" % listener.getsockname()[1]
        child = subprocess.Popen([str(viewer), address, str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(10)
                peer.sendall(b"RFB 003.008\n")
                assert exact(peer, 12) == b"RFB 003.008\n"
                peer.sendall(bytes([1, 5]))
                assert exact(peer, 1) == bytes([5])
                peer.sendall(public)
                bits = exact(peer, 4)
                assert bits == struct.pack(">I", 2048)
                values = exact(peer, 512)
                client_public = bits + values
                client_key = RSA.construct((int.from_bytes(values[:256], "big"), int.from_bytes(values[256:], "big")))
                ours = os.urandom(16)
                peer.sendall(struct.pack(">H", 256) + PKCS1_v1_5.new(client_key).encrypt(ours))
                assert exact(peer, 2) == struct.pack(">H", 256)
                theirs = PKCS1_v1_5.new(identity).decrypt(exact(peer, 256), b"invalid")
                assert len(theirs) == 16
                r = Records(peer, hashlib.sha1(ours + theirs).digest()[:16], hashlib.sha1(theirs + ours).digest()[:16])
                r.write(hashlib.sha1(public + client_public).digest())
                assert r.read(20) == hashlib.sha1(client_public + public).digest()
                r.write(bytes([2]))
                assert r.read(1) == bytes([0])
                assert r.read(r.read(1)[0]) == b"abcdefgh-full-password"
                r.write(bytes(4))
                assert r.read(1) == bytes([1])
                fmt = bytes([32, 24, 0, 1]) + struct.pack(">HHH", 255, 255, 255) + bytes([16, 8, 0, 0, 0, 0])
                r.write(struct.pack(">HH", 4, 3) + fmt + struct.pack(">I", 4) + b"RA2!")
                while True:
                    kind = r.read(1)[0]
                    if kind == 0:
                        assert r.read(19)[3:] == fmt
                    elif kind == 2:
                        count = struct.unpack(">H", r.read(3)[1:])[0]
                        r.read(4 * count)
                    elif kind == 3:
                        r.read(9)
                        break
                    else:
                        raise AssertionError(f"unexpected client message {kind}")
                r.write(bytes([0, 0, 0, 1]) + struct.pack(">HHHHi", 0, 0, 4, 3, 0) + bytes([3, 2, 1, 0]) * 12)
            out, err = child.communicate(timeout=10)
            assert child.returncode == 0, (out, err)
            assert image.read_bytes() == b"P6\n4 3\n255\n" + bytes([1, 2, 3]) * 12
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        # A different RSA key for the same address must be rejected before credentials.
        child = subprocess.Popen([str(viewer), address, str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(10)
                peer.sendall(b"RFB 003.008\n")
                exact(peer, 12)
                peer.sendall(bytes([1, 5]))
                assert exact(peer, 1) == bytes([5])
                replacement = RSA.generate(2048)
                peer.sendall(struct.pack(">I", 2048) + replacement.n.to_bytes(256, "big") + replacement.e.to_bytes(256, "big"))
                assert peer.recv(1) == b"", "changed server key was accepted"
            _, err = child.communicate(timeout=10)
            assert child.returncode != 0 and b"different RSA key" in err, err
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()


def main():
    exe = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="vncfree-ra2-") as appdata:
        with server(exe, appdata) as s:
            r, key = negotiate(s, "abcdefgh-full-password")
            assert r.read(4) == bytes(4)
            r.write(bytes([1]))
            init = r.read(24)
            width, height = struct.unpack(">HH", init[:4])
            assert width and height
            assert b"vncfree" in r.read(struct.unpack(">I", init[20:24])[0])
            # Request 8bpp true colour and a Raw framebuffer through encrypted records.
            pixel_format = bytes([8, 8, 0, 1]) + struct.pack(">HHH", 7, 7, 3) + bytes([5, 2, 0, 0, 0, 0])
            r.write(bytes(4) + pixel_format)
            r.write(bytes([2, 0, 0, 1]) + struct.pack(">i", 0))
            r.write(bytes([3, 0]) + struct.pack(">HHHH", 0, 0, width, height))
            update = r.read(4)
            assert update[:2] == bytes(2)
            count = struct.unpack(">H", update[2:])[0]
            assert count
            for _ in range(count):
                x, y, w, h, encoding = struct.unpack(">HHHHi", r.read(12))
                assert encoding == 0 and x + w <= width and y + h <= height
                r.read(w * h)
        protected = Path(appdata, "vncfree", "server-rsa.dpapi").read_bytes()
        with server(exe, appdata) as s:
            r, restarted = negotiate(s, "abcdefgh-WRONG-password")
            assert key == restarted, "RSA identity changed on restart"
            assert r.read(4) == struct.pack(">I", 1), "full password must be checked"
            n = struct.unpack(">I", r.read(4))[0]
            assert b"authentication failed" in r.read(n)
        assert protected == Path(appdata, "vncfree", "server-rsa.dpapi").read_bytes()
        with server(exe, appdata) as s:
            r, _ = negotiate(s, "abcdefgh-full-password")
            assert r.read(4) == bytes(4)
            r.write(bytes([1]), tamper=True)
            try:
                r.read(1)
            except (EOFError, ConnectionResetError):
                pass
            else:
                raise AssertionError("tampered ClientInit accepted")
        for mode, expected in [("offer", bytes([5, 19, 2])), ("require", bytes([19])), ("off", bytes([2]))]:
            with server(exe, appdata, mode) as s:
                exact(s, 12)
                s.sendall(b"RFB 003.008\n")
                assert exact(s, exact(s, 1)[0]) == expected
        viewer_test(exe, appdata)
    print("PASS: independent server/viewer RA2 exchange, viewer pinning, full password, encrypted 8bpp frame, tamper rejection, stable DPAPI identity, security policies")


if __name__ == "__main__":
    main()
