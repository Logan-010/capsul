use blake3::Hash;
use color_eyre::eyre::bail;
use dashmap::DashMap;
use iroh::{Endpoint, EndpointAddr, PublicKey, endpoint::Connection, protocol::ProtocolHandler};
use std::{collections::HashSet, path::PathBuf, sync::Arc};
use tokio::{fs, io, sync::RwLock};

/// Hashed data exchange over Iroh API
#[derive(Debug, Clone)]
pub struct Exchange {
    root: PathBuf,
    max_size: Option<u64>,
    authenticated_peers: Arc<RwLock<HashSet<PublicKey>>>,
    size: Arc<RwLock<u64>>,
    locks: Arc<DashMap<Hash, RwLock<()>>>,
}

impl Exchange {
    /// Iroh ALPN for protocol handlers
    pub const ALPN: &[u8] = b"/capsul/exchange/1.0.0";

    const MAX_SIZE: usize = 2 * 1024 * 1024;

    const MSG_LEN: usize = 3;
    const GET_MSG: &[u8] = b"GET";
    const PUT_MSG: &[u8] = b"PUT";
    const HAS_MSG: &[u8] = b"HAS";
    const OK_MSG: &[u8] = b"OKY";
    const NO_MSG: &[u8] = b"NOP";

    /// Create a new exchange object at a object store root with an optional max size.
    pub async fn new(root: PathBuf, max_size: Option<u64>) -> io::Result<Self> {
        if !fs::try_exists(&root).await? {
            fs::create_dir_all(&root).await?;
        }

        if !fs::metadata(&root).await?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "Path is not a directory",
            ));
        }

        let mut dir = fs::read_dir(&root).await?;
        let map = DashMap::new();
        let mut size = 0;

        while let Some(f) = dir.next_entry().await? {
            let meta = f.metadata().await?;
            let name = f
                .file_name()
                .into_string()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidFilename, "Invalid filename"))?;

            if meta.len() > Self::MAX_SIZE as u64 {
                tracing::warn!("Skipping too-large file ({name})");
                continue;
            }

            if !meta.is_file() {
                tracing::warn!("Skipping non-file ({name})");
                continue;
            }

            if let Ok(hash) = Hash::from_hex(&name) {
                size += meta.len();

                map.insert(hash, RwLock::new(()));
            } else {
                tracing::warn!("Skipping invalid file path in store ({name})");
            }
        }

        if let Some(m) = max_size
            && size > m
        {
            tracing::warn!("Store already exceeds max size");
        }

        Ok(Self {
            root,
            max_size,
            authenticated_peers: Arc::new(RwLock::new(HashSet::new())),
            size: Arc::new(RwLock::new(size)),
            locks: Arc::new(map),
        })
    }

    /// Add an authenticated peer to the exchange object
    pub async fn add_peer(&self, peer: PublicKey) {
        self.authenticated_peers.write().await.insert(peer);
    }

    /// Remove an authenticated peer
    pub async fn remove_peer(&self, peer: &PublicKey) {
        self.authenticated_peers.write().await.remove(peer);
    }

    /// Check if peer is authenticated
    pub async fn has_peer(&self, peer: &PublicKey) -> bool {
        self.authenticated_peers.read().await.contains(peer)
    }

    /// Get a hash from the local store
    pub async fn get(&self, hash: Hash) -> io::Result<Option<Vec<u8>>> {
        let lock = match self.locks.get(&hash) {
            Some(l) => l,
            None => return Ok(None),
        };
        let _guard = lock.read().await;

        let path = self.root.join(hash.to_string());

        let size = fs::metadata(&path).await?.len();
        if size > Self::MAX_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "File exceeds max size",
            ));
        }

        let data = fs::read(&path).await?;
        if blake3::hash(&data) != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hashes don't match",
            ));
        }

        Ok(Some(data))
    }

    /// Chech if local store has a hash
    pub async fn has(&self, hash: Hash) -> io::Result<bool> {
        let lock = match self.locks.get(&hash) {
            Some(l) => l,
            None => return Ok(false),
        };
        let _guard = lock.read().await;

        let path = self.root.join(hash.to_string());

        let size = fs::metadata(&path).await?.len();
        if size > Self::MAX_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "File exceeds max size",
            ));
        }

        let data = fs::read(&path).await?;

        Ok(blake3::hash(&data) == hash)
    }

    /// Put a hash into the local store
    pub async fn put<D: AsRef<[u8]>>(&self, data: D) -> io::Result<Hash> {
        let len = data.as_ref().len() as u64;

        if len > Self::MAX_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "Data exceeds max size",
            ));
        }

        if let Some(max) = self.max_size
            && *self.size.read().await + len > max
        {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "Size exceeds set max",
            ));
        }

        let hash = blake3::hash(data.as_ref());

        let lock = self.locks.entry(hash).or_insert(RwLock::new(()));
        let _guard = lock.write().await;

        let p = self.root.join(hash.to_string());
        fs::write(p, data).await?;

        *self.size.write().await += len;

        Ok(hash)
    }

    /// Fetch a hash from a remote
    pub async fn fetch(
        &self,
        endpoint: &Endpoint,
        from: impl Into<EndpointAddr>,
        hash: Hash,
    ) -> color_eyre::Result<Option<Vec<u8>>> {
        let conn = endpoint.connect(from, Self::ALPN).await?;

        let (mut tx, mut rx) = conn.open_bi().await?;
        tx.write_all(Self::GET_MSG).await?;
        tx.write_all(hash.as_slice()).await?;
        tx.finish()?;

        let mut code = [0u8; Self::MSG_LEN];
        rx.read_exact(&mut code).await?;

        if code == Self::NO_MSG {
            return Ok(None);
        } else if code != Self::OK_MSG {
            bail!("Invalid code");
        }

        let data = rx.read_to_end(Self::MAX_SIZE).await?;

        rx.stop(0u8.into())?;

        if blake3::hash(&data) != hash {
            bail!("Invalid data");
        }

        Ok(Some(data))
    }

    async fn task(&self, conn: Connection) -> color_eyre::Result<()> {
        if !self.has_peer(&conn.remote_id()).await {
            bail!("Unauthenticated peer");
        }

        let (mut tx, mut rx) = conn.accept_bi().await?;

        let mut code = [0u8; Self::MSG_LEN];
        rx.read_exact(&mut code).await?;

        match code.as_slice() {
            Self::GET_MSG => {
                let mut hash_raw = [0u8; 32];
                rx.read_exact(&mut hash_raw).await?;
                rx.stop(0u8.into())?;

                let hash = Hash::from_bytes(hash_raw);

                match self.get(hash).await? {
                    Some(v) => {
                        tx.write_all(Self::OK_MSG).await?;
                        tx.write_all(&v).await?;
                    }
                    None => {
                        tx.write_all(Self::NO_MSG).await?;
                    }
                }
            }
            Self::PUT_MSG => {
                let data = rx.read_to_end(Self::MAX_SIZE).await?;
                rx.stop(0u8.into())?;

                self.put(data).await?;
            }
            Self::HAS_MSG => {
                let mut hash_raw = [0u8; 32];
                rx.read_exact(&mut hash_raw).await?;
                rx.stop(0u8.into())?;

                let hash = Hash::from_bytes(hash_raw);

                if self.has(hash).await? {
                    tx.write_all(Self::OK_MSG).await?;
                } else {
                    tx.write_all(Self::NO_MSG).await?;
                }
            }
            _ => bail!("Invalid message"),
        }

        tx.finish()?;

        Ok(())
    }
}

impl ProtocolHandler for Exchange {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        if let Err(e) = self.task(connection).await {
            tracing::warn!("Exchange protocol error: {e:?}");
        }

        Ok(())
    }
}
