mod cli;
mod config;
mod node;

use clap::Parser;
use cli::Cli;
use color_eyre::eyre::ContextCompat;
use config::Config;
use directories::ProjectDirs;
use tokio::fs;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let cli = Cli::parse();

    if let Err(e) = tracing_subscriber::registry()
        .with(EnvFilter::new(&cli.logging))
        .with(tracing_subscriber::fmt::layer())
        .try_init()
    {
        eprintln!("Failed to initialize logger: {e:?}");
    }

    let config_path = match cli.config {
        Some(p) => p,
        None => ProjectDirs::from("com", "Logan-010", "capsul")
            .context("Expected project directories")?
            .config_dir()
            .join("config.toml"),
    };

    if let Some(p) = config_path.parent()
        && !fs::try_exists(p).await?
    {
        fs::create_dir_all(p).await?;
    }

    let config = if fs::try_exists(&config_path).await? {
        let data = fs::read_to_string(config_path).await?;
        Config::decode(data)?
    } else {
        let config = Config::new();
        fs::write(config_path, config.encode()?).await?;
        config
    };

    let node = node::build(&config).await?;

    Ok(())
}
