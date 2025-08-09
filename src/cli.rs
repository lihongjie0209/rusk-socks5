use clap::arg;
use clap::Parser;
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {



    /// The address to bind the server to
    #[arg(default_value = "127.0.0.1")]
    pub address: String,

    /// The port to bind the server to
    #[arg(short, long, default_value_t = 1080)]
    pub port: u16,

    /// Enable anonymous access

    #[arg(short, long, default_value_t = false)]
    pub allow_anonymous: bool,

    /// Username for authentication

    #[arg(short, long)]
    pub username: Option<String>,

    /// Password for authentication

    #[arg(short = 'P', long)]
    pub password: Option<String>,



    /// DNS cache max capacity
    #[arg(long, default_value_t = 10_000)]
    pub dns_cache_capacity: u64,

    /// DNS cache TTL seconds
    #[arg(long, default_value_t = 300)]
    pub dns_cache_ttl_secs: u64,

    /// Max concurrent connections
    #[arg(long, default_value_t = 1024)]
    pub max_connections: usize,

    /// Source IP whitelist rules (CIDR or wildcard). Repeat the flag to add multiple rules.
    #[arg(long, num_args = 1.., value_delimiter = ' ')]
    pub ip_whitelist: Vec<String>,
}