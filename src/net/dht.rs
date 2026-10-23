use color_eyre::eyre::{Context, bail};
use iroh::{Endpoint, EndpointId};
use iroh_mainline_endpoint_discovery::{AddrIndex, Publisher, Resolver, infohash_from_blake3};
use n0_mainline::{Dht, Id};
use std::time::Duration;
use tokio::time::timeout;

const DISCOVERY_DOMAIN: &str = "capsul-mainline-discovery-v1";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

pub struct PeerDiscovery {
    // Keep publisher alive to renew announcements.
    _publisher: Publisher,
    resolver: Resolver,
    infohash: Id,
    self_id: EndpointId,
}

fn discovery_infohash(psk: &[u8]) -> Id {
    let key = blake3::derive_key(DISCOVERY_DOMAIN, psk);

    let hash = blake3::Hash::from_bytes(key);
    Id::from(infohash_from_blake3(&hash))
}

impl PeerDiscovery {
    pub async fn start(endpoint: &Endpoint, psk: &[u8]) -> color_eyre::Result<Self> {
        let infohash = discovery_infohash(psk);

        let dht = Dht::client().context("failed to start Mainline DHT")?;

        if !dht.bootstrapped().await? {
            bail!("Mainline DHT bootstrap failed");
        }

        let index = AddrIndex::builder(dht.clone())
            .n0_defaults()
            .build()
            .await
            .context("failed to discover address index")?;

        let publisher = Publisher::new(endpoint.secret_key().clone(), dht.clone(), index.clone());

        publisher.add_infohash(infohash);

        let resolver = Resolver::new(dht, index);

        Ok(Self {
            _publisher: publisher,
            resolver,
            infohash,
            self_id: endpoint.id(),
        })
    }

    pub async fn find_peers(&self) -> color_eyre::Result<Vec<EndpointId>> {
        let peers = timeout(LOOKUP_TIMEOUT, self.resolver.resolve(self.infohash))
            .await
            .context("peer discovery timed out")??;

        Ok(peers.into_iter().filter(|id| *id != self.self_id).collect())
    }
}
