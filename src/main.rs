use clap::Parser;
use rusk_socks5::cli::CliArgs;
use env_logger::{Builder, Env};

#[tokio::main]
async fn main() {

    init_logger();

    let args = CliArgs::parse();


    let config = rusk_socks5::server::ServerConfig {
        address: args.address,
        port: args.port,
        allow_anonymous: args.allow_anonymous,
        username: args.username,
        password: args.password,
        dns_cache_capacity: args.dns_cache_capacity,
        dns_cache_ttl_secs: args.dns_cache_ttl_secs,
        max_connections: args.max_connections,
        ip_whitelist: args.ip_whitelist,
    };

    let mut server = rusk_socks5::server::SocksServer::new(config).await.unwrap();


    if let Err(e) = server.start().await {
        log::error!("Failed to start server: {}", e);
    }


}


fn init_logger() {
    Builder::from_env(Env::default().default_filter_or("info"))
        .init();
}
