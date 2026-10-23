use std::{fs, path::Path};

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use color_eyre::eyre::{WrapErr, ensure};
use rand::{TryRng, rngs::SysRng};

use crate::{manifest::EncryptedShardManifest, sharder::ShardManifest};

/// Key size in bytes
pub const KEY_SIZE: usize = 32;

/// Nonce size in bytes
pub const NONCE_SIZE: usize = 24;

/// Tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Encrypt a blob with an existing key, nonce, and AAD. Returns the generated tag.
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    data: &mut [u8],
) -> [u8; TAG_SIZE] {
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(nonce.into(), ad, data.into())
        .unwrap();

    assert!(tag.len() == TAG_SIZE, "Tag size is incorrect (not 16)");

    let mut tag_raw = [0u8; TAG_SIZE];
    tag_raw.clone_from_slice(&tag);

    tag_raw
}

/// Decrypt and authenticate a blob with an existing key, nonce, and AAD.
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    tag: &[u8; TAG_SIZE],
    data: &mut [u8],
) -> Result<(), chacha20poly1305::Error> {
    XChaCha20Poly1305::new(key.into()).decrypt_inout_detached(
        nonce.into(),
        ad,
        data.into(),
        tag.into(),
    )?;

    Ok(())
}

/// Encrypts all original and recovery shards in place.
///
/// Each file becomes `nonce || ciphertext || tag`, authenticated with its shard
/// filename as AAD. The returned manifest hashes these complete encrypted files.
/// All shards must exist and match their hashes. On error, shards already
/// processed remain encrypted; retain the original manifest until success.
pub fn encrypt_shards<P: AsRef<Path>>(
    from: P,
    key: &[u8; KEY_SIZE],
    manifest: ShardManifest,
) -> color_eyre::Result<EncryptedShardManifest> {
    let encrypt_kind = |hashes: Vec<blake3::Hash>, kind: char| {
        hashes
            .into_iter()
            .enumerate()
            .map(|(i, hash)| {
                let name = format!("{i}{kind}.shard");
                let path = from.as_ref().join(&name);
                let mut data = fs::read(&path).wrap_err_with(|| format!("Reading {name}"))?;
                ensure!(blake3::hash(&data) == hash, "Shard hash mismatch: {name}");

                let mut nonce = [0u8; NONCE_SIZE];
                SysRng.try_fill_bytes(&mut nonce)?;
                let tag = encrypt(key, &nonce, name.as_bytes(), &mut data);

                let mut encrypted = Vec::with_capacity(NONCE_SIZE + data.len() + TAG_SIZE);
                encrypted.extend_from_slice(&nonce);
                encrypted.extend_from_slice(&data);
                encrypted.extend_from_slice(&tag);
                fs::write(&path, &encrypted).wrap_err_with(|| format!("Writing {name}"))?;
                Ok(blake3::hash(&encrypted))
            })
            .collect::<color_eyre::Result<Vec<_>>>()
    };

    Ok(EncryptedShardManifest {
        config: manifest.config,
        original: encrypt_kind(manifest.original_shards, 'o')?,
        recovery: encrypt_kind(manifest.recovery_shards, 'r')?,
    })
}

/// Decrypts all shards in place and returns their plaintext hashes.
///
/// Requires the format produced by [`encrypt_shards`]. Each file's hash and
/// authentication tag are verified before it is overwritten. Missing, corrupt,
/// truncated, or unauthenticated shards return an error. Shards already
/// processed remain decrypted on failure.
pub fn decrypt_shards<P: AsRef<Path>>(
    from: P,
    key: &[u8; KEY_SIZE],
    manifest: EncryptedShardManifest,
) -> color_eyre::Result<ShardManifest> {
    let decrypt_kind = |hashes: Vec<blake3::Hash>, kind: char| {
        hashes
            .into_iter()
            .enumerate()
            .map(|(i, hash)| {
                let name = format!("{i}{kind}.shard");
                let path = from.as_ref().join(&name);
                let mut data = fs::read(&path).wrap_err_with(|| format!("Reading {name}"))?;
                ensure!(blake3::hash(&data) == hash, "Shard hash mismatch: {name}");
                ensure!(
                    data.len() >= NONCE_SIZE + TAG_SIZE,
                    "Truncated encrypted shard: {name}"
                );

                let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE].try_into()?;
                let tag_start = data.len() - TAG_SIZE;
                let tag: [u8; TAG_SIZE] = data[tag_start..].try_into()?;
                let plaintext = &mut data[NONCE_SIZE..tag_start];
                decrypt(key, &nonce, name.as_bytes(), &tag, plaintext)
                    .map_err(|_| color_eyre::eyre::eyre!("Shard authentication failed: {name}"))?;

                fs::write(&path, &*plaintext).wrap_err_with(|| format!("Writing {name}"))?;
                Ok(blake3::hash(plaintext))
            })
            .collect::<color_eyre::Result<Vec<_>>>()
    };

    Ok(ShardManifest {
        config: manifest.config,
        original_shards: decrypt_kind(manifest.original, 'o')?,
        recovery_shards: decrypt_kind(manifest.recovery, 'r')?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharder::{Decoder, Encoder, ShardingConfig};

    const DATA: &[u8] = b"Hello, encrypted shards!";
    const KEY: [u8; KEY_SIZE] = [42; KEY_SIZE];

    fn sample() -> (tempfile::TempDir, ShardManifest) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::write(&input, DATA).unwrap();
        let manifest = Encoder::new(ShardingConfig::new(DATA.len(), 16, 2))
            .encode(input.as_path(), dir.path())
            .unwrap();
        (dir, manifest)
    }

    #[test]
    fn test_shards_round_trip() {
        let (dir, original) = sample();
        let encrypted = encrypt_shards(dir.path(), &KEY, original.clone()).unwrap();
        for (kind, hashes) in [('o', &encrypted.original), ('r', &encrypted.recovery)] {
            for (i, hash) in hashes.iter().enumerate() {
                let data = fs::read(dir.path().join(format!("{i}{kind}.shard"))).unwrap();
                assert_eq!(data.len(), 16 + NONCE_SIZE + TAG_SIZE);
                assert_eq!(blake3::hash(&data), *hash);
            }
        }

        let restored = decrypt_shards(dir.path(), &KEY, encrypted).unwrap();
        assert_eq!(restored.original_shards, original.original_shards);
        assert_eq!(restored.recovery_shards, original.recovery_shards);
        // Recovery shards must also be usable after decryption.
        fs::remove_file(dir.path().join("0o.shard")).unwrap();
        let output = dir.path().join("output");
        Decoder::new()
            .decode(dir.path(), output.as_path(), restored, blake3::hash(DATA))
            .unwrap();
        assert_eq!(fs::read(output).unwrap(), DATA);
    }

    #[test]
    fn test_encrypt_rejects_missing_or_corrupt_shard() {
        for missing in [false, true] {
            let (dir, manifest) = sample();
            let path = dir.path().join("0o.shard");
            if missing {
                fs::remove_file(&path).unwrap();
            } else {
                fs::write(&path, b"corrupt").unwrap();
            }
            assert!(encrypt_shards(dir.path(), &KEY, manifest).is_err());
            if !missing {
                assert_eq!(fs::read(path).unwrap(), b"corrupt");
            }
        }
    }

    #[test]
    fn test_decrypt_rejects_wrong_key_without_overwriting() {
        let (dir, manifest) = sample();
        let encrypted = encrypt_shards(dir.path(), &KEY, manifest).unwrap();
        let path = dir.path().join("0o.shard");
        let before = fs::read(&path).unwrap();
        assert!(decrypt_shards(dir.path(), &[0; KEY_SIZE], encrypted).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn test_decrypt_rejects_corruption_and_truncation() {
        for (truncate, update_hash) in [(false, false), (false, true), (true, true)] {
            let (dir, manifest) = sample();
            let mut encrypted = encrypt_shards(dir.path(), &KEY, manifest).unwrap();
            let path = dir.path().join("0o.shard");
            let mut data = fs::read(&path).unwrap();
            if truncate {
                data.truncate(NONCE_SIZE + TAG_SIZE - 1);
            } else {
                data[NONCE_SIZE] ^= 1;
            }
            fs::write(&path, &data).unwrap();
            if update_hash {
                encrypted.original[0] = blake3::hash(&data);
            }
            assert!(decrypt_shards(dir.path(), &KEY, encrypted).is_err());
            assert_eq!(fs::read(path).unwrap(), data);
        }
    }

    #[test]
    fn test_decrypt_authenticates_shard_kind() {
        let (dir, manifest) = sample();
        let mut encrypted = encrypt_shards(dir.path(), &KEY, manifest).unwrap();
        let recovery = fs::read(dir.path().join("0r.shard")).unwrap();
        fs::write(dir.path().join("0o.shard"), &recovery).unwrap();
        encrypted.original[0] = encrypted.recovery[0];
        assert!(decrypt_shards(dir.path(), &KEY, encrypted).is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut pt = *b"Hello, world!";
        let key = [0u8; KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];

        let tag = encrypt(&key, &nonce, b"", &mut pt);
        decrypt(&key, &nonce, b"", &tag, &mut pt).unwrap();

        assert_eq!(&pt, b"Hello, world!");
    }
}
