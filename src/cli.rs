use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
pub struct Cli {
    /// Set log level
    #[arg(long, short = 'L', env = "RUST_LOG", default_value_t = String::from(concat!(env!("CARGO_PKG_NAME"), "=info,warn")))]
    pub logging: String,

    /// Custom config path
    #[arg(long, short = 'c', env = "CAPSUL_CONFIG")]
    pub config: Option<PathBuf>,
}
