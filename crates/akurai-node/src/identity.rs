//! Node cryptographic identity — a persistent X25519 static keypair.
//!
//! The private key is generated once from OS entropy, stored at
//! `config/identity.key` with `0600` perms, and **never** leaves the device or
//! appears in a log. The public key (`config/identity.pub`, Base64) is what the
//! control plane records and peers use to open a Noise_IK session to this node.

use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use akurai_common::b64;
use akurai_transport::Keypair;

/// A loaded node identity.
pub struct Identity {
    pub keypair: Keypair,
}

impl Identity {
    /// Load the existing identity, or generate and persist a fresh one.
    ///
    /// Idempotent: if `key_path` already holds a valid secret, it is reused
    /// (the public key is therefore stable across restarts). A new key is 32
    /// bytes of `/dev/urandom`, written `0600`.
    pub fn load_or_create(key_path: &Path, pub_path: &Path) -> io::Result<Self> {
        if let Ok(existing) = fs::read_to_string(key_path) {
            let secret = b64::decode_array::<32>(existing.trim()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "corrupt identity.key")
            })?;
            return Ok(Self {
                keypair: Keypair::from_secret(secret),
            });
        }

        let mut secret = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
        let keypair = Keypair::from_secret(secret);

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Private key: owner-only (0600) on Unix; on Windows the file inherits the
        // user-profile ACL (Unix mode bits don't exist there).
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        {
            use std::io::Write;
            let mut f = opts.open(key_path)?;
            f.write_all(b64::encode(&secret).as_bytes())?;
            f.write_all(b"\n")?;
        }
        // Public key: world-readable text.
        fs::write(pub_path, format!("{}\n", b64::encode(&keypair.public)))?;
        Ok(Self { keypair })
    }

    /// This node's Base64 public key (what the control plane stores).
    pub fn public_b64(&self) -> String {
        b64::encode(&self.keypair.public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("akv-id-test-{name}-{}", std::process::id()))
    }

    #[test]
    fn generates_persists_and_is_idempotent() {
        let dir = tmp("idem");
        let _ = fs::remove_dir_all(&dir);
        let key = dir.join("identity.key");
        let pubp = dir.join("identity.pub");

        let id1 = Identity::load_or_create(&key, &pubp).unwrap();
        // Public key on disk matches the in-memory key.
        let on_disk = fs::read_to_string(&pubp).unwrap();
        assert_eq!(on_disk.trim(), id1.public_b64());
        // The persisted public equals X25519(secret).
        let secret = b64::decode_array::<32>(fs::read_to_string(&key).unwrap().trim()).unwrap();
        assert_eq!(
            akurai_crypto::x25519::public_key(&secret),
            id1.keypair.public
        );

        // Reload: same key, not regenerated.
        let id2 = Identity::load_or_create(&key, &pubp).unwrap();
        assert_eq!(id1.keypair.public, id2.keypair.public);
        assert_eq!(id1.keypair.secret, id2.keypair.secret);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn private_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("perms");
        let _ = fs::remove_dir_all(&dir);
        let key = dir.join("identity.key");
        let pubp = dir.join("identity.pub");
        Identity::load_or_create(&key, &pubp).unwrap();
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity.key must be 0600, was {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
