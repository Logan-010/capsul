use crate::sharder::ShardManifest;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::io::{self, Cursor};

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub name: String,
    pub hash: Hash,
    pub shards: ShardManifest,
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
