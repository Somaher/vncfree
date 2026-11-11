//! Settings persisted with Windows DPAPI, scoped to the current Windows account.

use std::env::{self, VarError};

fn session_setting(key: &str) -> bool {
    matches!(key, "VNC_NO_UI" | "VNC_HIDE_CONSOLE" | "VNC_AUTOSTART")
}

/// Dialog edits override environment values, which override saved configuration.
/// An empty password means
/// no password was supplied, so it falls back to the saved one.
pub fn var(key: &str) -> Result<String, VarError> {
    #[cfg(windows)]
    if let Some(value) = windows::CONFIG
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|config| config.overrides.get(key))
    {
        return Ok(value.clone());
    }
    match env::var(key) {
        Ok(value) if key != "VNC_PASSWORD" || !value.is_empty() => return Ok(value),
        Err(error @ VarError::NotUnicode(_)) => return Err(error),
        _ => {}
    }
    if session_setting(key) {
        return Err(VarError::NotPresent);
    }
    #[cfg(windows)]
    if let Some(value) = windows::CONFIG
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|config| config.values.get(key))
    {
        return Ok(value.clone());
    }
    Err(VarError::NotPresent)
}

#[cfg(windows)]
pub use windows::{apply_saved, init, init_empty, save, saved};

#[cfg(windows)]
pub use windows::override_values;

pub fn enabled(key: &str) -> bool {
    var(key).is_ok_and(|value| !value.is_empty() && value != "0")
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use crate::Res;

    const MAGIC: &[u8] = b"vncfree-config-v1\n";
    const MAX_CONFIG: usize = 1024 * 1024;
    type Values = BTreeMap<String, String>;

    pub(super) struct Config {
        path: PathBuf,
        pub(super) values: Values,
        pub(super) overrides: Values,
    }

    pub(super) static CONFIG: Mutex<Option<Config>> = Mutex::new(None);

    /// Separate client and server files avoid reusing a remote host's password as
    /// the local server's password. No environment variables are changed.
    pub fn init(application: &str) -> Res<()> {
        init_empty(application)?;
        if let Some(values) = saved()? {
            apply_saved(values);
        }
        Ok(())
    }

    /// Prepare a UI session without applying saved settings until Load config.
    pub fn init_empty(application: &str) -> Res<()> {
        let appdata =
            std::env::var_os("APPDATA").ok_or("APPDATA is not set; cannot load settings")?;
        let path = PathBuf::from(appdata)
            .join("vncfree")
            .join(format!("{application}.cfg"));
        *CONFIG.lock().unwrap() = Some(Config {
            path,
            values: Values::new(),
            overrides: Values::new(),
        });
        Ok(())
    }

    /// Read a candidate without changing the active settings.
    pub fn saved() -> Res<Option<Values>> {
        let guard = CONFIG.lock().unwrap();
        let config = guard.as_ref().ok_or("settings have not been initialized")?;
        if !config.path.try_exists()? {
            return Ok(None);
        }
        let values = load(&config.path).map_err(|e| {
            format!(
                "could not load {}: {e}; delete this file to reset settings",
                config.path.display()
            )
        })?;
        Ok(Some(values))
    }

    pub fn apply_saved(values: Values) {
        if let Some(config) = CONFIG.lock().unwrap().as_mut() {
            config.values = values;
        }
    }

    /// Values explicitly edited in a dialog override the initial environment.
    pub fn override_values(values: Values) {
        if let Some(config) = CONFIG.lock().unwrap().as_mut() {
            config.overrides.extend(values);
        }
    }

    fn is_setting(key: &str) -> bool {
        key.starts_with("VNC_")
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    }

    /// Save environment settings plus explicit CLI/dialog values. Empty passwords
    /// never erase a stored password. Write only encrypted bytes to disk.
    pub fn save(overrides: &[(&str, &str)]) -> Res<()> {
        let mut guard = CONFIG.lock().unwrap();
        let config = guard.as_mut().ok_or("settings have not been initialized")?;
        let mut values = config.values.clone();
        values.retain(|key, _| !super::session_setting(key));
        for (key, value) in std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        {
            if is_setting(&key)
                && !super::session_setting(&key)
                && (key != "VNC_PASSWORD" || !value.is_empty())
            {
                values.insert(key, value);
            }
        }
        for (key, value) in config
            .overrides
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .chain(overrides.iter().copied())
        {
            if !is_setting(key) {
                return Err("invalid configuration setting name".into());
            }
            if !super::session_setting(key) && (key != "VNC_PASSWORD" || !value.is_empty()) {
                values.insert(key.to_string(), value.to_string());
            }
        }
        if values == config.values && config.path.exists() {
            return Ok(());
        }
        let encrypted = protect(&encode(&values)?, false)?;
        fs::create_dir_all(config.path.parent().unwrap())?;
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce)?;
        let temp = config
            .path
            .with_extension(format!("{:016x}.tmp", u64::from_le_bytes(nonce)));
        let result = (|| -> Res<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &config.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| format!("could not save {}: {e}", config.path.display()))?;
        config.values = values;
        Ok(())
    }

    fn load(path: &Path) -> Res<Values> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Values::new()),
            Err(e) => return Err(e.into()),
        };
        let mut encrypted = Vec::new();
        file.take((MAX_CONFIG + 1) as u64)
            .read_to_end(&mut encrypted)?;
        if encrypted.len() > MAX_CONFIG {
            return Err("configuration file is too large".into());
        }
        decode(&protect(&encrypted, true)?)
    }

    fn protect(data: &[u8], decrypt: bool) -> Res<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len().try_into()?,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            if decrypt {
                CryptUnprotectData(
                    &input,
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            } else {
                CryptProtectData(
                    &input,
                    null(),
                    null(),
                    null(),
                    null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            }
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as *mut _);
        }
        Ok(bytes)
    }

    fn encode(values: &Values) -> Res<Vec<u8>> {
        let mut out = MAGIC.to_vec();
        for (key, value) in values {
            for field in [key, value] {
                out.extend_from_slice(&u32::try_from(field.len())?.to_be_bytes());
                out.extend_from_slice(field.as_bytes());
            }
        }
        // Reserve space for DPAPI's header and authentication data.
        if out.len() > MAX_CONFIG / 2 {
            return Err("configuration settings are too large".into());
        }
        Ok(out)
    }

    fn decode(data: &[u8]) -> Res<Values> {
        let mut input = data
            .strip_prefix(MAGIC)
            .ok_or("unrecognized configuration format")?;
        let mut values = Values::new();
        while !input.is_empty() {
            let key = crate::text(&mut input)?;
            let value = crate::text(&mut input)?;
            if !is_setting(&key) || values.insert(key, value).is_some() {
                return Err("invalid or duplicate configuration setting".into());
            }
        }
        Ok(values)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encrypted_settings_round_trip_without_plaintext_credentials() {
            let values = Values::from([
                ("VNC_PASSWORD".into(), "a=secret\n\u{e9}\\password".into()),
                ("VNC_BIND".into(), "127.0.0.1:5900".into()),
                ("VNC_NO_UI".into(), "1".into()),
            ]);
            let plain = encode(&values).unwrap();
            let encrypted = protect(&plain, false).unwrap();
            assert!(!encrypted.windows(6).any(|bytes| bytes == b"secret"));
            assert_eq!(decode(&protect(&encrypted, true).unwrap()).unwrap(), values);
            let mut damaged = encrypted;
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            assert!(protect(&damaged, true).is_err());
        }

        #[test]
        fn malformed_settings_are_rejected() {
            assert!(decode(b"not a config").is_err());
            let mut truncated = MAGIC.to_vec();
            truncated.extend_from_slice(&1000u32.to_be_bytes());
            assert!(decode(&truncated).is_err());
            let invalid = Values::from([("APPDATA".into(), "invalid".into())]);
            assert!(decode(&encode(&invalid).unwrap()).is_err());
        }
    }
}
