//! CBOR metadata for locating, decrypting, and verifying a stored file.
//!
//! A [`Manifest`] includes the plaintext encryption key. Its encoded bytes are
//! neither encrypted nor authenticated; store them privately and obtain them
//! from a trusted source before using them to recover a file.

use crate::sharder::ShardingConfig;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::io::{self, Cursor};

/// Layout and ordered hashes of encrypted original and recovery shard files.
///
/// Created by [`crate::crypto::encrypt_shards`] and consumed by
/// [`crate::crypto::decrypt_shards`]. Hashes cover nonce, ciphertext, and tag.
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedShardManifest {
    pub(crate) config: ShardingConfig,
    pub(crate) original: Vec<Hash>,
    pub(crate) recovery: Vec<Hash>,
}

/// File metadata and secrets needed to decrypt and reconstruct its shards.
#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    /// User-supplied file name; not a validated or safe filesystem path.
    pub name: String,
    /// Plaintext XChaCha20-Poly1305 key. Keep this manifest private.
    pub key: [u8; 32],
    /// Expected BLAKE3 hash of the complete original file.
    pub hash: Hash,
    /// Layout and hashes of the encrypted shard files.
    pub shards: EncryptedShardManifest,
}

impl Manifest {
    /// Serializes this manifest to CBOR, including the plaintext encryption key.
    ///
    /// Returns an error if CBOR serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, ciborium::ser::Error<io::Error>> {
        let mut writer = Cursor::new(Vec::new());
        ciborium::into_writer(self, &mut writer)?;
        Ok(writer.into_inner())
    }

    /// Deserializes a manifest from CBOR.
    ///
    /// Returns an error for malformed CBOR or missing or incompatible fields.
    /// This does not authenticate the metadata or validate its shard layout.
    pub fn decode<D: AsRef<[u8]>>(data: D) -> Result<Self, ciborium::de::Error<io::Error>> {
        ciborium::from_reader(Cursor::new(data.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            name: "notes-📦.txt".into(),
            key: [42; 32],
            hash: blake3::hash(b"file contents"),
            shards: EncryptedShardManifest {
                config: ShardingConfig::new(13, 16, 2),
                original: vec![blake3::hash(b"original 0"), blake3::hash(b"original 1")],
                recovery: vec![blake3::hash(b"recovery 0"), blake3::hash(b"recovery 1")],
            },
        }
    }

    #[test]
    fn test_manifest_round_trip() {
        let manifest = sample();
        let encoded = manifest.encode().unwrap();
        let decoded = Manifest::decode(&encoded).unwrap();

        assert_eq!(decoded.name, manifest.name);
        assert_eq!(decoded.key, manifest.key);
        assert_eq!(decoded.hash, manifest.hash);
        assert_eq!(decoded.shards.original, manifest.shards.original);
        assert_eq!(decoded.shards.recovery, manifest.shards.recovery);
        // Re-encoding also checks the private layout fields are preserved.
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn test_manifest_rejects_truncated_data() {
        let encoded = sample().encode().unwrap();
        for length in 0..encoded.len() {
            assert!(Manifest::decode(&encoded[..length]).is_err());
        }
    }

    #[test]
    fn test_manifest_rejects_invalid_or_incomplete_data() {
        for data in [&[0xff][..], &[0xf6][..], &[0xa0][..]] {
            assert!(Manifest::decode(data).is_err());
        }
    }
}
