use blake3::Hash;
use color_eyre::eyre::bail;
use iroh::{Endpoint, EndpointAddr, PublicKey, endpoint::Connection, protocol::ProtocolHandler};
use rand::{TryRng, rngs::SysRng};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct PeerAuth {
    psk: [u8; 32],
    peers: Arc<RwLock<HashSet<PublicKey>>>,
}

const AUTH_DOMAIN: &str = "Capsul peer authentication PSK v1.0.0";

impl PeerAuth {
    pub const ALPN: &[u8] = b"/capsul/auth/1.0.0";

    const HANDSHAKE: &[u8] = b"wwwwwh";

    const CHALLENGE_SIZE: usize = 32;

    const MSG_LEN: usize = 3;
    const OK_MSG: &[u8] = b"OKY";
    const NO_MSG: &[u8] = b"NOP";

    pub fn new(psk: Vec<u8>) -> Self {
        let key = blake3::derive_key(AUTH_DOMAIN, &psk);

        Self {
            psk: key,
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

    pub async fn authenticate(
        &self,
        endpoint: &Endpoint,
        with: impl Into<EndpointAddr>,
    ) -> color_eyre::Result<()> {
        let conn = endpoint.connect(with, Self::ALPN).await?;

        let (mut tx, mut rx) = conn.open_bi().await?;

        tx.write_all(Self::HANDSHAKE).await?;

        let mut their_nonce = [0u8; Self::CHALLENGE_SIZE];
        rx.read_exact(&mut their_nonce).await?;

        let mine = blake3::keyed_hash(&self.psk, &their_nonce);

        tx.write_all(mine.as_slice()).await?;

        let mut code = [0u8; Self::MSG_LEN];
        rx.read_exact(&mut code).await?;
        if code == Self::NO_MSG {
            bail!("Unauthorized");
        } else if code != Self::OK_MSG {
            bail!("Invalid message");
        }

        let mut nonce = [0u8; Self::CHALLENGE_SIZE];
        SysRng.try_fill_bytes(&mut nonce)?;
        tx.write_all(&nonce).await?;

        let expected = blake3::keyed_hash(&self.psk, &nonce);

        let mut actual_raw = [0u8; Self::CHALLENGE_SIZE];
        rx.read_exact(&mut actual_raw).await?;
        let actual = Hash::from_bytes(actual_raw);

        if actual == expected {
            tx.write_all(Self::OK_MSG).await?;
        } else {
            tx.write_all(Self::NO_MSG).await?;
            bail!("Unauthorized");
        }

        tx.finish()?;

        Ok(())
    }

    pub async fn task(&self, conn: Connection) -> color_eyre::Result<()> {
        let (mut tx, mut rx) = conn.accept_bi().await?;

        let mut handshake = [0u8; Self::HANDSHAKE.len()];
        rx.read_exact(&mut handshake).await?;

        if handshake != Self::HANDSHAKE {
            bail!("Invalid handshake");
        }

        let mut nonce = [0u8; Self::CHALLENGE_SIZE];
        SysRng.try_fill_bytes(&mut nonce)?;
        tx.write_all(&nonce).await?;

        let expected = blake3::keyed_hash(&self.psk, &nonce);

        let mut actual_raw = [0u8; Self::CHALLENGE_SIZE];
        rx.read_exact(&mut actual_raw).await?;
        let actual = Hash::from_bytes(actual_raw);

        if actual != expected {
            tx.write_all(Self::NO_MSG).await?;
            bail!("Unauthorized");
        }

        tx.write_all(Self::OK_MSG).await?;

        let mut their_nonce = [0u8; Self::CHALLENGE_SIZE];
        rx.read_exact(&mut their_nonce).await?;

        let mine = blake3::keyed_hash(&self.psk, &their_nonce);

        tx.write_all(mine.as_slice()).await?;
        tx.finish()?;

        let mut code = [0u8; Self::MSG_LEN];
        rx.read_exact(&mut code).await?;
        if code == Self::NO_MSG {
            bail!("Unauthorized");
        } else if code != Self::OK_MSG {
            bail!("Invalid message");
        }

        self.peers.write().await.insert(conn.remote_id());

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
