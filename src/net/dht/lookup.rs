use blake3::Hash;
use color_eyre::eyre::Context;
use iroh::EndpointId;
use iroh_mainline_endpoint_discovery::{AddrIndex, Resolver, infohash_from_blake3};
use n0_mainline::{Dht, Id};
use std::time::Duration;
use tokio::time::timeout;

pub struct HashLookup {
    resolver: Resolver,
    lookup_timeout: Duration,
}

impl HashLookup {
    pub async fn new(
        dht: Dht,
        index: AddrIndex,
        timeout: Option<Duration>,
    ) -> color_eyre::Result<Self> {
        let resolver = Resolver::new(dht, index);

        Ok(Self {
            resolver,
            lookup_timeout: timeout.unwrap_or(Duration::from_secs(15)),
        })
    }

    pub async fn find_peers(&self, hash: &Hash) -> color_eyre::Result<Vec<EndpointId>> {
        let infohash = Id::from(infohash_from_blake3(hash));

        let peers = timeout(self.lookup_timeout, self.resolver.resolve(infohash))
            .await
            .context("hash lookup timed out")??;

        Ok(peers)
    }
}
