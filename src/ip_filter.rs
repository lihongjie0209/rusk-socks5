use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Rule {
    Cidr(IpNet),
    WildcardV4 { prefix: String }, // e.g. 192.168.*.* or 10.*
}

#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    rules: Vec<Rule>,
}

impl IpFilter {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn from_strings(patterns: &[String]) -> Result<Self, String> {
        let mut filter = Self::new();
        for p in patterns {
            filter.add_rule(p)?;
        }
        Ok(filter)
    }

    pub fn add_rule(&mut self, pattern: &str) -> Result<(), String> {
        // Try CIDR first
        if let Ok(net) = pattern.parse::<IpNet>() {
            self.rules.push(Rule::Cidr(net));
            return Ok(());
        }

        // Simple wildcard support for IPv4: segments separated by '.', '*' matches any segment.
        if Self::is_ipv4_wildcard(pattern) {
            let prefix = pattern.to_string();
            self.rules.push(Rule::WildcardV4 { prefix });
            return Ok(());
        }

        Err(format!("Invalid IP rule pattern: {}", pattern))
    }

    pub fn allows(&self, ip: &IpAddr) -> bool {
        if self.rules.is_empty() {
            // No whitelist configured -> allow all
            return true;
        }
        self.rules.iter().any(|r| match (r, ip) {
            (Rule::Cidr(net), ip) => net.contains(ip),
            (Rule::WildcardV4 { prefix }, IpAddr::V4(v4)) => {
                let ip_str = v4.to_string();
                Self::ipv4_wildcard_match(prefix, &ip_str)
            }
            _ => false,
        })
    }

    fn is_ipv4_wildcard(p: &str) -> bool {
        // Accept patterns like "192.168.*.*", "10.*", "*.*.*.*"
        p.split('.').all(|s| s == "*" || s.parse::<u8>().is_ok())
    }

    fn ipv4_wildcard_match(pattern: &str, ip: &str) -> bool {
        let p_parts: Vec<&str> = pattern.split('.').collect();
        let ip_parts: Vec<&str> = ip.split('.').collect();
        if p_parts.len() != ip_parts.len() {
            return false;
        }
        for (p, v) in p_parts.iter().zip(ip_parts.iter()) {
            if *p != "*" && *p != *v {
                return false;
            }
        }
        true
    }
}
