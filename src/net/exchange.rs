use blake3::Hash;
use color_eyre::eyre::bail;
use dashmap::DashMap;
use iroh::{Endpoint, EndpointAddr, endpoint::Connection, protocol::ProtocolHandler};
use std::{path::PathBuf, sync::Arc};
use tokio::{fs, io, sync::RwLock};

#[derive(Debug, Clone)]
pub struct Exchange {
    root: PathBuf,
    locks: Arc<DashMap<Hash, RwLock<()>>>,
}

impl Exchange {
    pub const ALPN: &[u8] = b"/capsul/exchange/1.0.0";

    pub async fn new(root: PathBuf) -> io::Result<Self> {
        if !fs::try_exists(&root).await? {
            fs::create_dir_all(&root).await?;
        }

        if !fs::metadata(&root).await?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "Path is not a directory",
            ));
        }

        Ok(Self {
            root,
            locks: Arc::new(DashMap::new()),
        })
    }

    pub async fn fetch(
        &self,
        endpoint: &Endpoint,
        from: impl Into<EndpointAddr>,
        hash: Hash,
    ) -> color_eyre::Result<Option<Vec<u8>>> {
        let conn = endpoint.connect(from, Self::ALPN).await?;

        let mut tx = conn.open_uni().await?;
        tx.write_all(hash.as_slice()).await?;
        tx.finish()?;

        let mut rx = conn.accept_uni().await?;

        let mut code = [0u8; 2];
        rx.read_exact(&mut code).await?;

        if &code == b"NO" {
            return Ok(None);
        } else if &code != b"OK" {
            bail!("Invalid code");
        }

        let data = rx.read_to_end(2 * 1024 * 1024).await?;

        if blake3::hash(&data) != hash {
            bail!("Invalid data");
        }

        Ok(Some(data))
    }

    pub async fn get(&self, hash: Hash) -> io::Result<Option<Vec<u8>>> {
        let lock = match self.locks.get(&hash) {
            Some(l) => l,
            None => return Ok(None),
        };
        let _guard = lock.read().await;

        let path = self.root.join(hash.to_string());
        let data = fs::read(&path).await?;
        if blake3::hash(&data) != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hashes don't match",
            ));
        }

        Ok(Some(data))
    }

    pub async fn put<D: AsRef<[u8]>>(&self, data: D) -> io::Result<Hash> {
        let hash = blake3::hash(data.as_ref());

        let lock = self.locks.entry(hash).or_insert(RwLock::new(()));
        let _guard = lock.write().await;

        let p = self.root.join(hash.to_string());
        fs::write(p, data).await?;

        Ok(hash)
    }
}

impl ProtocolHandler for Exchange {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        if let Err(e) = task(self, connection).await {
            tracing::warn!("Exchange protocol error: {e:?}");
        }

        Ok(())
    }
}

async fn task(exchange: &Exchange, conn: Connection) -> color_eyre::Result<()> {
    let mut rx = conn.accept_uni().await?;

    let mut hash_raw = [0u8; 32];
    rx.read_exact(&mut hash_raw).await?;
    rx.stop(0u8.into())?;

    let hash = Hash::from_bytes(hash_raw);

    match exchange.get(hash).await? {
        Some(v) => {
            let mut tx = conn.open_uni().await?;
            tx.write_all(b"OK").await?;
            tx.write_all(&v).await?;
            tx.finish()?;
        }
        None => {
            let mut tx = conn.open_uni().await?;
            tx.write_all(b"NO").await?;
            tx.finish()?;
        }
    }

    Ok(())
}
