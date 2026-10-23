use crate::sharder::ShardingConfig;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::io::{self, Cursor};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedShardManifest {
    pub(crate) config: ShardingConfig,
    pub(crate) original: Vec<Hash>,
    pub(crate) recovery: Vec<Hash>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub name: String,
    pub key: [u8; 32],
    pub hash: Hash,
    pub shards: EncryptedShardManifest,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, ciborium::ser::Error<io::Error>> {
        let mut writer = Cursor::new(Vec::new());
        ciborium::into_writer(self, &mut writer)?;
        Ok(writer.into_inner())
    }

    pub fn decode<D: AsRef<[u8]>>(data: D) -> Result<Self, ciborium::de::Error<io::Error>> {
        ciborium::from_reader(Cursor::new(data.as_ref()))
    }
}
