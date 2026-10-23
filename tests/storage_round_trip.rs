use capsul::{
    crypto::{KEY_SIZE, decrypt_shards, encrypt_shards},
    manifest::Manifest,
    sharder::{Decoder, Encoder, ShardingConfig},
};
use std::fs;

#[test]
fn test_recovery_with_persisted_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    let manifest_path = dir.path().join("manifest.cbor");
    // Multiple full shards and a partial final shard, including binary data.
    let data: Vec<u8> = (0..257).map(|i| i as u8).collect();
    fs::write(&input, &data).unwrap();

    let shards = Encoder::new(ShardingConfig::new(data.len(), 64, 2))
        .encode(input.as_path(), dir.path())
        .unwrap();
    let key = [42; KEY_SIZE];
    let manifest = Manifest {
        name: "input".into(),
        key,
        hash: blake3::hash(&data),
        shards: encrypt_shards(dir.path(), &key, shards).unwrap(),
    };
    fs::write(&manifest_path, manifest.encode().unwrap()).unwrap();
    fs::remove_file(&input).unwrap();

    let manifest = Manifest::decode(fs::read(manifest_path).unwrap()).unwrap();
    let shards = decrypt_shards(dir.path(), &manifest.key, manifest.shards).unwrap();
    // Decryption currently requires all encrypted shards. Erasure recovery is
    // exercised after decryption, with one missing and one corrupt original.
    fs::remove_file(dir.path().join("0o.shard")).unwrap();
    fs::write(dir.path().join("4o.shard"), b"corrupt").unwrap();
    Decoder::new()
        .decode(dir.path(), output.as_path(), shards, manifest.hash)
        .unwrap();

    assert_eq!(fs::read(output).unwrap(), data);
}
