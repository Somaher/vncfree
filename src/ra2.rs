//! RFB security type 5 (RA2): RSA PKCS#1 v1.5 exchange and AES-128-EAX.
//! Wire format: https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst
//! RSA operations use Windows CNG; private identity files use current-user DPAPI.

use crate::{blob, rd, u16r, u32r, u8r, Res};
use eax::{
    aead::{AeadInPlace, KeyInit},
    Eax,
};
use sha1::{Digest, Sha1};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    ptr::{null, null_mut},
};
use subtle::ConstantTimeEq;
use windows_sys::Win32::Security::Cryptography::*;

fn status(code: i32) -> Res<()> {
    if code < 0 {
        Err(format!("Windows RSA operation failed ({code:#x})").into())
    } else {
        Ok(())
    }
}

struct Provider(BCRYPT_ALG_HANDLE);
impl Provider {
    fn new() -> Res<Self> {
        let mut p = Self(null_mut());
        unsafe {
            status(BCryptOpenAlgorithmProvider(
                &mut p.0,
                BCRYPT_RSA_ALGORITHM,
                null(),
                0,
            ))?;
        }
        Ok(p)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}

pub struct Identity {
    private: zeroize::Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

struct Key(BCRYPT_KEY_HANDLE);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.0);
        }
    }
}
impl Key {
    fn generate(bits: u32) -> Res<Self> {
        let p = Provider::new()?;
        let mut k = Self(null_mut());
        unsafe {
            status(BCryptGenerateKeyPair(p.0, &mut k.0, bits, 0))?;
            status(BCryptFinalizeKeyPair(k.0, 0))?;
        }
        Ok(k)
    }
    fn import(data: &[u8], private: bool) -> Res<Self> {
        let p = Provider::new()?;
        let mut k = Self(null_mut());
        unsafe {
            status(BCryptImportKeyPair(
                p.0,
                null_mut(),
                if private {
                    BCRYPT_RSAFULLPRIVATE_BLOB
                } else {
                    BCRYPT_RSAPUBLIC_BLOB
                },
                &mut k.0,
                data.as_ptr(),
                data.len().try_into()?,
                0,
            ))?;
        }
        Ok(k)
    }
    fn export(&self, private: bool) -> Res<Vec<u8>> {
        let kind = if private {
            BCRYPT_RSAFULLPRIVATE_BLOB
        } else {
            BCRYPT_RSAPUBLIC_BLOB
        };
        let mut n = 0;
        unsafe {
            status(BCryptExportKey(
                self.0,
                null_mut(),
                kind,
                null_mut(),
                0,
                &mut n,
                0,
            ))?;
        }
        let mut data = vec![0; n as usize];
        unsafe {
            status(BCryptExportKey(
                self.0,
                null_mut(),
                kind,
                data.as_mut_ptr(),
                n,
                &mut n,
                0,
            ))?;
        }
        data.truncate(n as usize);
        Ok(data)
    }
    fn crypt(&self, input: &[u8], decrypt: bool, size: usize) -> Res<Vec<u8>> {
        let mut out = vec![0; size];
        let mut n = 0;
        unsafe {
            let op = if decrypt {
                BCryptDecrypt
            } else {
                BCryptEncrypt
            };
            status(op(
                self.0,
                input.as_ptr(),
                input.len().try_into()?,
                null(),
                null_mut(),
                0,
                out.as_mut_ptr(),
                size.try_into()?,
                &mut n,
                BCRYPT_PAD_PKCS1,
            ))?;
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

impl Identity {
    fn from_key(key: Key) -> Res<Self> {
        let b = key.export(false)?;
        let word = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        let (bits, e, n) = (word(4), word(8), word(12));
        if n != bits.div_ceil(8) || e > n || b.len() != 24 + e + n {
            return Err("invalid CNG RSA public key".into());
        }
        let mut public = (bits as u32).to_be_bytes().to_vec();
        public.extend_from_slice(&b[24 + e..]);
        public.resize(4 + n * 2, 0);
        public[4 + n * 2 - e..].copy_from_slice(&b[24..24 + e]);
        Ok(Self {
            private: zeroize::Zeroizing::new(key.export(true)?),
            public,
        })
    }
    pub fn new() -> Res<Self> {
        let path = crate::wire::state_dir().map(|d| d.join("server-rsa.dpapi"));
        if let Some(p) = &path {
            match std::fs::File::open(p) {
                Ok(f) => {
                    let mut encrypted = Vec::new();
                    f.take(32769).read_to_end(&mut encrypted)?;
                    if encrypted.len() > 32768 {
                        return Err("RSA identity file too large".into());
                    }
                    let private =
                        zeroize::Zeroizing::new(crate::config::protect(&encrypted, true)?);
                    return Self::from_key(Key::import(&private, true)?);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let me = Self::from_key(Key::generate(2048)?)?;
        if let Some(p) = path {
            std::fs::create_dir_all(p.parent().unwrap())?;
            let encrypted = crate::config::protect(&me.private, false)?;
            // Never replace an identity another server instance has just created.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)?;
            f.write_all(&encrypted)?;
            f.sync_all()?;
        }
        Ok(me)
    }
}

fn read_public(r: &mut impl Read) -> Res<(Vec<u8>, Key)> {
    let bits = u32r(r)?;
    if !(2048..=8192).contains(&bits) || bits % 8 != 0 {
        return Err("RA2 requires an RSA key of 2048..8192 bits".into());
    }
    let size = (bits / 8) as usize;
    let values = blob(r, size * 2)?;
    let exponent = &values[size..];
    let start = exponent
        .iter()
        .position(|&b| b != 0)
        .ok_or("invalid RSA exponent")?;
    let exponent = &exponent[start..];
    if exponent.len() > 4 {
        return Err("RSA exponent too large".into());
    }
    let mut b = Vec::new();
    for word in [
        BCRYPT_RSAPUBLIC_MAGIC,
        bits,
        exponent.len() as u32,
        size as u32,
        0,
        0,
    ] {
        b.extend_from_slice(&word.to_le_bytes());
    }
    b.extend_from_slice(exponent);
    b.extend_from_slice(&values[..size]);
    let key = Key::import(&b, false)?;
    let mut public = bits.to_be_bytes().to_vec();
    public.extend_from_slice(&values);
    Ok((public, key))
}

/// RealVNC-compatible display fingerprint; pinning separately uses full SHA-256.
pub fn viewer_fingerprint(public: &[u8]) -> String {
    digest(public, &[])[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("-")
}

fn digest(a: &[u8], b: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn exchange(
    tcp: &mut TcpStream,
    key: &Key,
    peer: &Key,
    size: usize,
    peer_size: usize,
) -> Res<([u8; 16], [u8; 16])> {
    let mut ours = [0; 16];
    getrandom::fill(&mut ours)?;
    let encrypted = peer.crypt(&ours, false, peer_size)?;
    tcp.write_all(&(encrypted.len() as u16).to_be_bytes())?;
    tcp.write_all(&encrypted)?;
    if u16r(tcp)? as usize != size {
        return Err("invalid RA2 encrypted random length".into());
    }
    let ciphertext = blob(tcp, size)?;
    // On invalid PKCS#1 padding, continue with an unpredictable random secret.
    // The peer sees only the normal encrypted proof followed by a failed proof;
    // no padding-specific response is sent (implicit rejection).
    let mut theirs = [0; 16];
    getrandom::fill(&mut theirs)?;
    if let Ok(value) = key.crypt(&ciphertext, true, size) {
        if value.len() == 16 {
            theirs.copy_from_slice(&value);
        }
    }
    Ok((ours, theirs))
}

pub fn server(
    mut tcp: TcpStream,
    me: &Identity,
) -> Res<(
    crate::wire::WireRead,
    crate::wire::WireWrite,
    zeroize::Zeroizing<Vec<u8>>,
)> {
    tcp.write_all(&me.public)?;
    let (client, peer) = read_public(&mut tcp)?;
    let key = Key::import(&me.private, true)?;
    let (ours, theirs) = exchange(
        &mut tcp,
        &key,
        &peer,
        (me.public.len() - 4) / 2,
        (client.len() - 4) / 2,
    )?;
    let (mut r, mut w) = crate::wire::ra2(
        tcp,
        &digest(&ours, &theirs)[..16],
        &digest(&theirs, &ours)[..16],
    )?;
    w.write_all(&digest(&me.public, &client))?;
    if !bool::from(rd::<20>(&mut r)?.ct_eq(&digest(&client, &me.public))) {
        return Err("RA2 key verification failed".into());
    }
    w.write_all(&[2])?; // Password only, full UTF-8 value (not VNC DES).
    let n = u8r(&mut r)? as usize;
    let _username = blob(&mut r, n)?;
    let n = u8r(&mut r)? as usize;
    let password = zeroize::Zeroizing::new(blob(&mut r, n)?);
    Ok((r, w, password))
}

pub fn client(
    tcp: TcpStream,
    host: &str,
    username: &str,
    password: &str,
) -> Res<(crate::wire::WireRead, crate::wire::WireWrite)> {
    client_with_verifier(tcp, username, password, |server| {
        crate::wire::check_known(&format!("ra2:{host}"), &crate::wire::fingerprint(server))
    })
}

fn client_with_verifier(
    mut tcp: TcpStream,
    username: &str,
    password: &str,
    verify: impl FnOnce(&[u8]) -> Res<()>,
) -> Res<(crate::wire::WireRead, crate::wire::WireWrite)> {
    if password.is_empty() || password.len() > 255 || username.len() > 255 {
        return Err(
            "RA2 credentials require a password and at most 255 UTF-8 bytes per field".into(),
        );
    }
    let (server, peer) = read_public(&mut tcp)?;
    verify(&server)?;
    let me = Identity::from_key(Key::generate(u32::from_be_bytes(server[..4].try_into()?))?)?;
    tcp.write_all(&me.public)?;
    let key = Key::import(&me.private, true)?;
    let (ours, theirs) = exchange(
        &mut tcp,
        &key,
        &peer,
        (me.public.len() - 4) / 2,
        (server.len() - 4) / 2,
    )?;
    let (mut r, mut w) = crate::wire::ra2(
        tcp,
        &digest(&ours, &theirs)[..16],
        &digest(&theirs, &ours)[..16],
    )?;
    w.write_all(&digest(&me.public, &server))?;
    if !bool::from(rd::<20>(&mut r)?.ct_eq(&digest(&server, &me.public))) {
        return Err("RA2 key verification failed".into());
    }
    let subtype = u8r(&mut r)?;
    let user = match subtype {
        1 => username,
        2 => "",
        _ => return Err("unsupported RA2 authentication subtype".into()),
    };
    let mut credentials = zeroize::Zeroizing::new(vec![user.len() as u8]);
    credentials.extend_from_slice(user.as_bytes());
    credentials.push(password.len() as u8);
    credentials.extend_from_slice(password.as_bytes());
    w.write_all(&credentials)?;
    eprintln!(
        "session encrypted with RSA-AES128; RSA key {}",
        crate::wire::fingerprint(&server)
    );
    Ok((r, w))
}

pub(crate) struct Cipher {
    cipher: Eax<aes::Aes128>,
    counter: u128,
    failed: bool,
}
impl Cipher {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            cipher: Eax::new_from_slice(key).expect("AES128 key"),
            counter: 0,
            failed: false,
        }
    }
    fn nonce(&mut self) -> io::Result<[u8; 16]> {
        if self.failed {
            return Err(io::Error::other("RA2 cipher closed"));
        }
        let nonce = self.counter.to_le_bytes();
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            self.failed = true;
            io::Error::other("RA2 nonce exhausted")
        })?;
        Ok(nonce)
    }
    pub(crate) fn read(&mut self, r: &mut impl Read) -> io::Result<Vec<u8>> {
        let nonce = self.nonce()?;
        // Any incomplete/invalid record permanently poisons the stream.
        self.failed = true;
        let mut header = [0; 2];
        r.read_exact(&mut header)?;
        let mut data = vec![0; u16::from_be_bytes(header) as usize];
        r.read_exact(&mut data)?;
        let mut tag = [0; 16];
        r.read_exact(&mut tag)?;
        self.cipher
            .decrypt_in_place_detached((&nonce).into(), &header, &mut data, (&tag).into())
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid RA2 authentication tag")
            })?;
        self.failed = false;
        Ok(data)
    }
    pub(crate) fn write(&mut self, w: &mut impl Write, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let nonce = self.nonce()?;
        self.failed = true;
        let n = data.len().min(8192);
        let header = (n as u16).to_be_bytes();
        let mut sealed = data[..n].to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce).into(), &header, &mut sealed)
            .map_err(|_| io::Error::other("RA2 encryption failed"))?;
        w.write_all(&header)?;
        w.write_all(&sealed)?;
        w.write_all(&tag)?;
        self.failed = false;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn eax_record_matches_independent_pycryptodome_vector() {
        let key: Vec<u8> = (0..16).collect();
        let mut cipher = Cipher::new(&key);
        let mut record = Vec::new();
        cipher.write(&mut record, b"hello").unwrap();
        let hex = record
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, "000510f92a33a721ccbc272bcb96040554d71643980f50");
    }

    #[test]
    fn records_reject_tampering_replay_and_truncation() {
        let mut record = Vec::new();
        Cipher::new(&[7; 16]).write(&mut record, b"secret").unwrap();
        for at in 0..record.len() {
            let mut altered = record.clone();
            altered[at] ^= 1;
            let mut reader = Cipher::new(&[7; 16]);
            assert!(reader.read(&mut &altered[..]).is_err());
            assert!(
                reader.read(&mut &record[..]).is_err(),
                "failure poisons cipher"
            );
        }
        let mut reader = Cipher::new(&[7; 16]);
        assert_eq!(reader.read(&mut &record[..]).unwrap(), b"secret");
        assert!(
            reader.read(&mut &record[..]).is_err(),
            "nonce prevents replay"
        );
        for n in 0..record.len() {
            assert!(Cipher::new(&[7; 16]).read(&mut &record[..n]).is_err());
        }
    }

    #[test]
    fn nonce_exhaustion_is_terminal() {
        let mut cipher = Cipher::new(&[7; 16]);
        cipher.counter = u128::MAX;
        assert!(cipher.write(&mut Vec::new(), b"x").is_err());
        assert!(cipher.write(&mut Vec::new(), b"x").is_err());
    }

    #[test]
    fn public_key_lengths_are_bounded_before_reading() {
        for bits in [0u32, 128, 1024, 2049, 8193, u32::MAX] {
            assert!(read_public(&mut &bits.to_be_bytes()[..]).is_err());
        }
    }

    #[test]
    fn rsa_ciphertext_uses_pkcs1_and_wrong_padding_is_rejected() {
        let key = Key::generate(2048).unwrap();
        let public = Key::import(&key.export(false).unwrap(), false).unwrap();
        let ciphertext = public.crypt(&[42; 16], false, 256).unwrap();
        assert_eq!(ciphertext.len(), 256);
        assert_eq!(key.crypt(&ciphertext, true, 256).unwrap(), [42; 16]);
        assert!(key.crypt(&[0; 256], true, 256).is_err());
    }

    #[test]
    fn handshake_and_bidirectional_large_session_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let identity = Identity::from_key(Key::generate(2048).unwrap()).unwrap();
            let (mut r, mut w, password) = server(tcp, &identity).unwrap();
            assert_eq!(password.as_slice(), "longer-than-eight-??".as_bytes());
            w.write_all(&0u32.to_be_bytes()).unwrap();
            let mut data = vec![0; 200000];
            r.read_exact(&mut data).unwrap();
            assert_eq!(data, vec![19; 200000]);
            w.write_all(&data).unwrap();
        });
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let (mut r, mut w) =
            client_with_verifier(tcp, "", "longer-than-eight-??", |_| Ok(())).unwrap();
        assert_eq!(rd::<4>(&mut r).unwrap(), [0; 4]);
        w.write_all(&vec![19; 200000]).unwrap();
        let mut data = vec![0; 200000];
        r.read_exact(&mut data).unwrap();
        assert_eq!(data, vec![19; 200000]);
        far.join().unwrap();
    }

    #[test]
    fn untrusted_key_is_rejected_before_sending_client_key_or_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let far = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let identity = Identity::from_key(Key::generate(2048).unwrap()).unwrap();
            tcp.write_all(&identity.public).unwrap();
            assert_eq!(tcp.read(&mut [0; 1]).unwrap(), 0);
        });
        assert!(
            client_with_verifier(TcpStream::connect(addr).unwrap(), "", "password", |_| Err(
                "changed key".into()
            ))
            .is_err()
        );
        far.join().unwrap();
    }
}
