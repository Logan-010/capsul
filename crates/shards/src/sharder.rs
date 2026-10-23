use crate::padding;
use blake3::{Hash, Hasher};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct ShardingConfig {
    file_size: usize,
    shard_size: usize,
    original_shards: usize,
    recovery_shards: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShardManifest {
    config: ShardingConfig,
    original_shards: Vec<Hash>,
    recovery_shards: Vec<Hash>,
}

impl ShardingConfig {
    pub fn new(file_size: usize, shard_size: usize, recovery_shards: usize) -> Self {
        assert!(shard_size > 4, "Shard size is too small");
        assert!(recovery_shards > 0, "Recovery shards is set to 0");

        Self {
            file_size,
            shard_size,
            original_shards: file_size.div_ceil(shard_size - 4),
            recovery_shards,
        }
    }
}

pub struct Encoder {
    inner: ReedSolomonEncoder,
    config: ShardingConfig,
}

impl Encoder {
    pub fn new(config: ShardingConfig) -> Self {
        Self {
            inner: ReedSolomonEncoder::new(
                config.original_shards,
                config.recovery_shards,
                config.shard_size,
            )
            .expect("Valid encoder"),
            config,
        }
    }

    pub fn encode<P: AsRef<Path>>(&mut self, from: P, to: P) -> io::Result<ShardManifest> {
        let mut buf = vec![0u8; self.config.shard_size];
        let mut file = File::open(from.as_ref())?;

        tracing::trace!("Encoding {}", from.as_ref().display());

        let original_shards = (0..self.config.original_shards)
            .map(|n| {
                let read = file.read(&mut buf[4..])?;
                padding::pad_data(&mut buf, read);
                self.inner
                    .add_original_shard(&buf)
                    .map_err(io::Error::other)?;

                let name = format!("{}o.shard", n);
                let out_path = to.as_ref().join(&name);

                tracing::trace!("Writing shard {}", out_path.display());

                fs::write(&out_path, &buf)?;

                let hash = Hasher::new().update_mmap_rayon(&out_path)?.finalize();

                io::Result::Ok(hash)
            })
            .collect::<io::Result<Vec<Hash>>>()?;

        let recovery_shards = self
            .inner
            .encode()
            .map_err(io::Error::other)?
            .recovery_iter()
            .enumerate()
            .map(|(n, r)| {
                let name = format!("{}r.shard", n);
                let out_path = to.as_ref().join(&name);

                tracing::trace!("Writing shard {}", out_path.display());

                fs::write(&out_path, r)?;

                let hash = Hasher::new().update_mmap_rayon(&out_path)?.finalize();

                io::Result::Ok(hash)
            })
            .collect::<io::Result<Vec<Hash>>>()?;

        Ok(ShardManifest {
            config: self.config.clone(),
            original_shards,
            recovery_shards,
        })
    }
}

#[derive(Default)]
pub struct Decoder;

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode<P: AsRef<Path>>(
        &self,
        from: P,
        to: P,
        manifest: ShardManifest,
        hash: Hash,
    ) -> io::Result<()> {
        let mut decoder = ReedSolomonDecoder::new(
            manifest.config.original_shards,
            manifest.config.recovery_shards,
            manifest.config.shard_size,
        )
        .map_err(|_| io::Error::other("Invalid manifest"))?;

        let original_shards = manifest
            .original_shards
            .iter()
            .enumerate()
            .map(|(i, h)| (i, format!("{i}o.shard"), h))
            .map(|(i, n, h)| {
                let p = from.as_ref().join(&n);
                (i, n, h, p)
            })
            .filter(|(_, _, _, p)| p.exists())
            .filter(|(_, _, h, p)| {
                Hasher::new()
                    .update_mmap_rayon(p)
                    .map(|hs| hs.finalize() == **h)
                    .unwrap_or(false)
            })
            .map(|(i, _, _, p)| (i, p))
            .collect::<Vec<_>>();
        let recovery_shards = manifest
            .recovery_shards
            .iter()
            .enumerate()
            .map(|(i, h)| (i, format!("{i}r.shard"), h))
            .map(|(i, n, h)| {
                let p = from.as_ref().join(&n);
                (i, n, h, p)
            })
            .filter(|(_, _, _, p)| p.exists())
            .filter(|(_, _, h, p)| {
                Hasher::new()
                    .update_mmap_rayon(p)
                    .map(|hs| hs.finalize() == **h)
                    .unwrap_or(false)
            })
            .map(|(i, _, _, p)| (i, p))
            .collect::<Vec<_>>();

        if original_shards.len() + recovery_shards.len() < manifest.original_shards.len() {
            return Err(io::Error::other("Not enough shards"));
        }

        let mut remaining = manifest.original_shards.len();
        let mut original_data = HashMap::new();

        for (i, p) in original_shards {
            if remaining == 0 {
                break;
            }

            let data = fs::read(p)?;
            decoder
                .add_original_shard(i, &data)
                .map_err(io::Error::other)?;
            original_data.insert(i, data);

            remaining -= 1;
        }

        for (i, p) in recovery_shards {
            if remaining == 0 {
                break;
            }

            let data = fs::read(p)?;
            decoder
                .add_recovery_shard(i, data)
                .map_err(io::Error::other)?;

            remaining -= 1;
        }

        assert!(remaining == 0, "Should have had enough shards");

        let decoded = decoder.decode().map_err(io::Error::other)?;
        let mut out = File::create(to.as_ref())?;

        for i in 0..manifest.original_shards.len() {
            let shard = original_data
                .get(&i)
                .map(Vec::as_slice)
                .or_else(|| decoded.restored_original(i))
                .ok_or_else(|| io::Error::other("Missing original shard"))?;
            let raw = padding::unpad_data(shard)
                .ok_or_else(|| io::Error::other("Invalid shard padding"))?;

            out.write_all(raw)?;
        }

        if Hasher::new().update_mmap_rayon(to)?.finalize() != hash {
            Err(io::Error::other("Hashes don't match"))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"Hello, world!";
    const SHARD_SIZE: usize = 16;

    fn encode_sample() -> (tempfile::TempDir, ShardManifest) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::write(&input, DATA).unwrap();

        let config = ShardingConfig::new(DATA.len(), SHARD_SIZE, 2);
        let manifest = Encoder::new(config)
            .encode(input.as_path(), dir.path())
            .unwrap();

        (dir, manifest)
    }

    #[test]
    fn test_config_shard_count() {
        // Four bytes of each shard are reserved for the length prefix.
        assert_eq!(ShardingConfig::new(12, 16, 2).original_shards, 1);
        assert_eq!(ShardingConfig::new(13, 16, 2).original_shards, 2);
        assert_eq!(ShardingConfig::new(24, 16, 2).original_shards, 2);
    }

    #[test]
    #[should_panic(expected = "Shard size is too small")]
    fn test_config_rejects_small_shards() {
        ShardingConfig::new(12, 4, 2);
    }

    #[test]
    #[should_panic(expected = "Recovery shards is set to 0")]
    fn test_config_rejects_zero_recovery_shards() {
        ShardingConfig::new(12, 16, 0);
    }

    #[test]
    fn test_encode_creates_shards_and_manifest() {
        let (dir, manifest) = encode_sample();

        assert_eq!(manifest.config.file_size, DATA.len());
        assert_eq!(manifest.original_shards.len(), 2);
        assert_eq!(manifest.recovery_shards.len(), 2);

        for (suffix, hashes) in [
            ("o", &manifest.original_shards),
            ("r", &manifest.recovery_shards),
        ] {
            for (i, hash) in hashes.iter().enumerate() {
                let shard = fs::read(dir.path().join(format!("{i}{suffix}.shard"))).unwrap();
                assert_eq!(shard.len(), SHARD_SIZE);
                assert_eq!(blake3::hash(&shard), *hash);
            }
        }

        let mut restored = Vec::new();
        for i in 0..manifest.original_shards.len() {
            let shard = fs::read(dir.path().join(format!("{i}o.shard"))).unwrap();
            restored.extend_from_slice(padding::unpad_data(&shard).unwrap());
        }
        assert_eq!(restored, DATA);
    }

    #[test]
    fn test_encode_missing_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("missing");
        let mut encoder = Encoder::new(ShardingConfig::new(DATA.len(), SHARD_SIZE, 2));

        let error = encoder.encode(input.as_path(), dir.path()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let (dir, manifest) = encode_sample();
        let output = dir.path().join("output");

        Decoder::new()
            .decode(dir.path(), output.as_path(), manifest, blake3::hash(DATA))
            .unwrap();

        assert_eq!(fs::read(output).unwrap(), DATA);
    }

    #[test]
    fn test_decode_recovers_missing_original_shard() {
        let (dir, manifest) = encode_sample();
        let output = dir.path().join("output");
        fs::remove_file(dir.path().join("0o.shard")).unwrap();

        Decoder::new()
            .decode(dir.path(), output.as_path(), manifest, blake3::hash(DATA))
            .unwrap();

        assert_eq!(fs::read(output).unwrap(), DATA);
    }

    #[test]
    fn test_decode_recovers_missing_last_or_all_original_shards() {
        for missing in [&[1][..], &[0, 1][..]] {
            let (dir, manifest) = encode_sample();
            let output = dir.path().join("output");
            for i in missing {
                fs::remove_file(dir.path().join(format!("{i}o.shard"))).unwrap();
            }

            Decoder::new()
                .decode(dir.path(), output.as_path(), manifest, blake3::hash(DATA))
                .unwrap();

            assert_eq!(fs::read(output).unwrap(), DATA);
        }
    }

    #[test]
    fn test_decode_recovers_corrupt_original_shard() {
        let (dir, manifest) = encode_sample();
        let output = dir.path().join("output");
        fs::write(dir.path().join("0o.shard"), [0u8; SHARD_SIZE]).unwrap();

        Decoder::new()
            .decode(dir.path(), output.as_path(), manifest, blake3::hash(DATA))
            .unwrap();

        assert_eq!(fs::read(output).unwrap(), DATA);
    }

    #[test]
    fn test_decode_rejects_incorrect_hash() {
        let (dir, manifest) = encode_sample();
        let output = dir.path().join("output");

        let error = Decoder::new()
            .decode(
                dir.path(),
                output.as_path(),
                manifest,
                blake3::hash(b"incorrect data"),
            )
            .unwrap_err();

        assert_eq!(error.to_string(), "Hashes don't match");
    }

    #[test]
    fn test_decode_rejects_insufficient_shards() {
        let (dir, manifest) = encode_sample();
        let output = dir.path().join("output");
        for name in ["0o.shard", "1o.shard", "0r.shard", "1r.shard"] {
            fs::remove_file(dir.path().join(name)).unwrap();
        }

        let error = Decoder::new()
            .decode(dir.path(), output.as_path(), manifest, blake3::hash(DATA))
            .unwrap_err();

        assert_eq!(error.to_string(), "Not enough shards");
        assert!(!output.exists());
    }
}
