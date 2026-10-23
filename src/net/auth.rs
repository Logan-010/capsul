use blake3::Hash;
use iroh::{EndpointAddr, PublicKey, endpoint::Connection, protocol::ProtocolHandler};
use rand::{TryRng, rngs::SysRng};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct PeerAuth {
    psk: Vec<u8>,
    peers: Arc<RwLock<HashSet<PublicKey>>>,
}

impl PeerAuth {
    pub const ALPN: &[u8] = b"/capsul/auth/1.0.0";

    const CHALLENGE_SIZE: usize = 32;

    const MSG_LEN: usize = 3;
    const OK_MSG: &[u8] = b"OKY";
    const NO_MSG: &[u8] = b"NOP";

    pub fn new(psk: Vec<u8>) -> Self {
        Self {
            psk,
            peers: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Remove an authenticated peer
    pub async fn revoke_peer(&self, peer: &PublicKey) {
        self.peers.write().await.remove(peer);
    }

    /// Check if peer is authenticated
    pub async fn has_peer(&self, peer: &PublicKey) -> bool {
        self.peers.read().await.contains(peer)
    }

    pub async fn authenticate(&self, with: impl Into<EndpointAddr>) -> color_eyre::Result<()> {
        Ok(())
    }

    pub async fn task(&self, conn: Connection) -> color_eyre::Result<()> {
        let (mut tx, mut rx) = conn.accept_bi().await?;

        let mut nonce = [0u8; Self::CHALLENGE_SIZE];
        SysRng.try_fill_bytes(&mut nonce)?;
        tx.write_all(&nonce).await?;

        let expected = blake3::keyed_hash(&nonce, &self.psk);

        let mut actual_raw = [0u8; Self::CHALLENGE_SIZE];
        rx.read_exact(&mut actual_raw).await?;
        let actual = Hash::from_bytes(actual_raw);

        if actual == expected {
            tx.write_all(Self::OK_MSG).await?;
        } else {
            tx.write_all(Self::NO_MSG).await?;
        }

        Ok(())
    }
}

impl ProtocolHandler for PeerAuth {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        if let Err(e) = self.task(connection).await {
            tracing::warn!("Auth error: {e:?}");
        }

        Ok(())
    }
}
