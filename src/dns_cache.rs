use std::net::SocketAddr;
use std::time::Duration;
use moka::future::Cache;

pub struct DnsCache {
    cache: Cache<String, Vec<SocketAddr>>,
}

impl DnsCache {
    pub fn new_default() -> Self {
        Self::new(10_000, Duration::from_secs(300))
    }

    pub fn new(max_capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();
        Self { cache }
    }

    pub async fn resolve(&self, host: &str, port: u16) -> crate::errors::Result<Vec<SocketAddr>> {
        let key = format!("{}:{}", host, port);
        if let Some(v) = self.cache.get(&key).await {
            log::debug!("DNS cache hit: key={}, addrs={}", key, v.len());
            return Ok(v);
        }
        log::debug!("DNS cache miss: key={}, resolving...", key);
        let lookup_host = format!("{}:{}", host, port);
        let res = tokio::net::lookup_host(lookup_host)
            .await
            .map_err(|e| crate::errors::ServerError::ConnectionError(e.to_string()))?;
        let addrs: Vec<SocketAddr> = res.collect();
        log::debug!("DNS cache insert: key={}, addrs={}", key, addrs.len());
        self.cache.insert(key, addrs.clone()).await;
        Ok(addrs)
    }
}
