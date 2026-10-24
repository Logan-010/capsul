use base64::{Engine, engine::general_purpose::STANDARD};
use color_eyre::eyre::bail;
use directories::ProjectDirs;
use iroh::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    identity: String,
    pub listen_addr: SocketAddr,
    pub store: PathBuf,
    pub psk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dht_timeout: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_peers: Vec<PublicKey>,
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
            listen_addr: "[::]:9011".parse().expect("Valid address"),
            store,
            psk: STANDARD.encode(rand::random::<[u8; 32]>()),
            dht_timeout: None,
            store_size: None,
            direct_peers: Vec::new(),
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

    pub fn encode(&self) -> color_eyre::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn decode<D: AsRef<str>>(data: D) -> color_eyre::Result<Self> {
        Ok(toml::from_str(data.as_ref())?)
    }
}
