use std::sync::Arc;
use crate::errors::{Result, ServerError};
use log;
use tokio::net::TcpListener;
use crate::handlers::ConnectionHandler;
use crate::dns_cache::DnsCache;
use std::time::Duration;
use crate::ip_filter::IpFilter;
use tokio::sync::Semaphore;
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub allow_anonymous: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub dns_cache_capacity: u64,
    pub dns_cache_ttl_secs: u64,
    pub max_connections: usize,
    pub ip_whitelist: Vec<String>,
}

pub struct SocksServer {
    // Add fields as necessary, such as a listener, configuration, etc.
    config: Arc<ServerConfig>,
    listener: Option<TcpListener>,
    dns_cache: Arc<DnsCache>,
    conn_semaphore: Arc<Semaphore>,
    ip_filter: Arc<IpFilter>,
}

impl SocksServer {
    pub async fn new(config: ServerConfig) -> Result<Self> {
        let dns_cache = DnsCache::new(
            config.dns_cache_capacity,
            Duration::from_secs(config.dns_cache_ttl_secs),
        );
        let conn_semaphore = Semaphore::new(config.max_connections);
        let ip_filter = IpFilter::from_strings(&config.ip_whitelist)
            .map_err(|e| ServerError::Unknown(e))?;
        Ok(SocksServer {
            config: Arc::new(config),
            listener: None,
            dns_cache: Arc::new(dns_cache),
            conn_semaphore: Arc::new(conn_semaphore),
            ip_filter: Arc::new(ip_filter),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.listener =
            Some(TcpListener::bind(format!("{}:{}", self.config.address, self.config.port)).await?);

        log::info!(
            "Socks5 server started on {}:{}, dns_cache_capacity={}, ttl_secs={}, max_connections={}, whitelist_rules={}",
            self.config.address,
            self.config.port,
            self.config.dns_cache_capacity,
            self.config.dns_cache_ttl_secs,
            self.config.max_connections,
            self.config.ip_whitelist.len()
        );

        loop {
            let (socket, addr) = match self.listener.as_mut().unwrap().accept().await {
                Ok((socket, addr)) => (socket, addr),
                Err(e) => return Err(ServerError::ConnectionError(e.to_string())),
            };

            // IP whitelist check
            let src_ip = addr.ip();
            if !self.ip_filter.allows(&src_ip) {
                log::warn!("Rejected connection from {}, not in whitelist", addr);
                // Drop immediately
                continue;
            }

            // Acquire connection permit
            let permit = match self.conn_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    log::warn!("Connection limit reached ({}). Rejecting {}", self.config.max_connections, addr);
                    continue;
                }
            };

            log::info!("Accepted connection from {}", addr);

            let server_config = self.config.clone();
            let dns_cache = self.dns_cache.clone();
            // Keep permit alive for the lifetime of the task
            tokio::spawn(async move {
                let _permit = permit; // held until task ends
                let mut  handler = ConnectionHandler::new(socket, addr, server_config, dns_cache);
                if let Err(e) = handler.handle().await {
                    log::error!("Error handling connection from {}: {}", addr, e);

                    handler.close().await.unwrap_or_else(|e| {
                        log::error!("Failed to close connection from {}: {}", addr, e);
                    });
                }

                log::info!("Connection from {} closed", addr);
            });
        }
    }
}
