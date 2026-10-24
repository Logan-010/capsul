use crate::config::Config;
use capsul::net::{
    Exchange, PeerAuth,
    dht::{HashLookup, PeerDiscovery, init as dht_init},
};
use color_eyre::eyre::Context;
use iroh::{Endpoint, endpoint::presets, protocol::Router};
use iroh_mdns_address_lookup::MdnsAddressLookup;

pub struct Node {
    pub endpoint: Endpoint,
    pub router: Router,
    pub discovery: PeerDiscovery,
    pub auth: PeerAuth,
    pub hash_lookup: HashLookup,
    pub hash_exchange: Exchange,
}

pub async fn build(config: &Config) -> color_eyre::Result<Node> {
    let key = config.identity().context("Invalid identity in config")?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .address_lookup(MdnsAddressLookup::builder().build(key.public())?)
        .bind_addr(config.listen_addr)?
        .bind()
        .await?;

    let (dht, index) = dht_init().await?;

    let discovery = PeerDiscovery::new(
        &endpoint,
        dht.clone(),
        index.clone(),
        config.psk.as_bytes(),
        config.dht_timeout,
    )
    .await?;

    let auth = PeerAuth::new(config.psk.as_bytes().to_vec());

    let hash_lookup = HashLookup::new(dht, index, config.dht_timeout).await?;

    let hash_exchange =
        Exchange::new(config.store.clone(), config.store_size, auth.clone()).await?;

    let router = Router::builder(endpoint.clone())
        .accept(PeerAuth::ALPN, auth.clone())
        .accept(Exchange::ALPN, hash_exchange.clone())
        .spawn();

    Ok(Node {
        endpoint,
        router,
        discovery,
        auth,
        hash_lookup,
        hash_exchange,
    })
}
