use base64::{Engine, engine::general_purpose::STANDARD};
use color_eyre::eyre::bail;
use directories::ProjectDirs;
use iroh::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    identity: String,
    store: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    direct_peers: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dht_peers: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        let identity = STANDARD.encode(SecretKey::generate().to_bytes());
        let store = ProjectDirs::from("com", "Logan-010", "capsul")
            .expect("Expected project directories")
            .data_dir()
            .join("capsul_store");

        Self {
            identity,
            store,
            direct_peers: Vec::new(),
            dht_peers: Vec::new(),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity(&self) -> color_eyre::Result<SecretKey> {
        let data = STANDARD.decode(&self.identity)?;
        if data.len() != 32 {
            bail!("Invalid key");
        }
        let mut raw_key = [0u8; 32];
        raw_key.clone_from_slice(&data);
        Ok(SecretKey::from_bytes(&raw_key))
    }

    pub fn store(&self) -> &Path {
        &self.store
    }

    pub fn direct_peers(&self) -> &[PublicKey] {
        &self.direct_peers
    }

    pub fn dht_peers(&self) -> &[String] {
        &self.dht_peers
    }
}
