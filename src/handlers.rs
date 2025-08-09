use crate::dns_cache::DnsCache;
use crate::server::ServerConfig;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub struct ConnectionHandler {
    socket: tokio::net::TcpStream,
    _address: SocketAddr,
    config: Arc<ServerConfig>,
    dns_cache: Arc<DnsCache>,
}

#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AuthMethod {
    NoAuthRequired = 0x00,
    GSSAPI = 0x01,
    UsernamePassword = 0x02,
    NoAcceptableMethods = 0xFF,
}
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UDPAssociate = 0x03,
}

impl ConnectionHandler {
    pub fn new(socket: tokio::net::TcpStream, address: SocketAddr, config: Arc<ServerConfig>, dns_cache: Arc<DnsCache>) -> Self {
        ConnectionHandler {
            socket,
            _address: address,
            config,
            dns_cache,
        }
    }

    pub async fn handle(&mut self) -> crate::errors::Result<()> {
        let version = self.socket.read_u8().await?;

        if version != 5 {
            return Err(crate::errors::ServerError::UnsupportedProtocolVersion);
        }

        let num_methods = self.socket.read_u8().await? as usize;

        let mut methods = vec![0u8; num_methods];

        self.socket.read_exact(&mut methods).await?;

        if methods
            .iter()
            .any(|&x| x == AuthMethod::UsernamePassword as u8)
            && self.config.username.is_some()
            && self.config.password.is_some()
        {
            // Respond with the Username/Password method
            self.socket
                .write_all(&[5, AuthMethod::UsernamePassword as u8])
                .await?;

            // Handle Username/Password authentication

            self.socket.read_u8().await?;

            let mut username = vec![0u8; self.socket.read_u8().await? as usize];
            self.socket.read_exact(&mut username).await?;
            let mut password = vec![0u8; self.socket.read_u8().await? as usize];
            self.socket.read_exact(&mut password).await?;

            let username = String::from_utf8(username)
                .map_err(|_| crate::errors::ServerError::InvalidRequestFormat)?;
            let password = String::from_utf8(password)
                .map_err(|_| crate::errors::ServerError::InvalidRequestFormat)?;

            if username.eq(self.config.username.as_ref().unwrap())
                && password.eq(self.config.password.as_ref().unwrap())
            {
                // Authentication successful
                self.socket.write_all(&[5, 0]).await?; // 0 means success
            } else {
                // Authentication failed
                self.socket.write_all(&[5, 1]).await?; // 1 means failure
                return Err(crate::errors::ServerError::AuthenticationFailed(
                    "Invalid username or password".to_string(),
                ));
            }
        } else if methods.contains(&(AuthMethod::NoAuthRequired as u8)) {
            // Respond with No Authentication Required

            if self.config.allow_anonymous {
                self.socket
                    .write_all(&[5, AuthMethod::NoAuthRequired as u8])
                    .await?;
            } else {
                // If anonymous access is not allowed, send No Acceptable Methods
                self.socket
                    .write_all(&[5, AuthMethod::NoAcceptableMethods as u8])
                    .await?;
                return Err(crate::errors::ServerError::AuthenticationFailed(
                    "Anonymous access is not allowed".to_string(),
                ));
            }
        } else {
            // No acceptable methods found
            self.socket
                .write_all(&[5, AuthMethod::NoAcceptableMethods as u8])
                .await?;
            return Err(crate::errors::ServerError::AuthenticationFailed(
                "No acceptable authentication methods".to_string(),
            ));
        }

        // Read the request
        let version = self.socket.read_u8().await?;
        if version != 5 {
            return Err(crate::errors::ServerError::UnsupportedProtocolVersion);
        }

        let command = Command::try_from(self.socket.read_u8().await?)
            .map_err(|_| crate::errors::ServerError::InvalidRequestFormat)?;

        match command {
            Command::Connect => {}
            Command::Bind => {
                self.socket
                    .write_all(&[5, 7, 0, AddressType::IPv4.into(), 0, 0, 0, 0])
                    .await?;

                return Err(crate::errors::ServerError::UnsupportedCmd(
                    Command::Bind.into(),
                ));
            }

            Command::UDPAssociate => {
                self.socket
                    .write_all(&[5, 7, 0, AddressType::IPv4.into(), 0, 0, 0, 0])
                    .await?;
                return Err(crate::errors::ServerError::UnsupportedCmd(
                    Command::UDPAssociate.into(),
                ));
            }
        };

        let _reserved = self.socket.read_u8().await?; // Reserved byte, should be 0x00

        let address_type = AddressType::try_from(self.socket.read_u8().await?)
            .map_err(|_| crate::errors::ServerError::InvalidRequestFormat)?;

        let address;

        match address_type {
            AddressType::IPv4 => {
                let mut ip = [0u8; 4];
                self.socket.read_exact(&mut ip).await?;
                address = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            }
            AddressType::DomainName => {
                let length = self.socket.read_u8().await? as usize;
                let mut domain = vec![0u8; length];
                self.socket.read_exact(&mut domain).await?;
                address = String::from_utf8(domain)
                    .map_err(|_| crate::errors::ServerError::InvalidRequestFormat)?;
            }
            AddressType::IPv6 => {
                let mut ip = [0u8; 16];
                self.socket.read_exact(&mut ip).await?;
                address = format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    u16::from_be_bytes([ip[0], ip[1]]),
                    u16::from_be_bytes([ip[2], ip[3]]),
                    u16::from_be_bytes([ip[4], ip[5]]),
                    u16::from_be_bytes([ip[6], ip[7]]),
                    u16::from_be_bytes([ip[8], ip[9]]),
                    u16::from_be_bytes([ip[10], ip[11]]),
                    u16::from_be_bytes([ip[12], ip[13]]),
                    u16::from_be_bytes([ip[14], ip[15]])
                );
            }
        }

        let port = self.socket.read_u16().await?;

        let target_address = format!("{}:{}", address, port);

        log::info!("Connecting to target address: {}", target_address);

        // Resolve and connect via DNS cache for domain names
        let target_socket_res: Result<tokio::net::TcpStream, std::io::Error> = match address_type {
            AddressType::DomainName => {
                let addrs = self
                    .dns_cache
                    .resolve(&address, port)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

                // Try each resolved address until one connects
                let mut last_err: Option<std::io::Error> = None;
                let mut success: Option<tokio::net::TcpStream> = None;
                for addr in addrs {
                    match tokio::net::TcpStream::connect(addr).await {
                        Ok(s) => {
                            success = Some(s);
                            break;
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
                if let Some(s) = success { Ok(s) } else { Err(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Failed to connect to any resolved address"))) }
            }
            _ => tokio::net::TcpStream::connect(&target_address).await,
        };

        match target_socket_res {
            Ok(mut target_socket) => {
                log::info!(
                    "Successfully connected to target address: {}",
                    target_address
                );

                // Send the response
                self.socket
                    .write_all(&[5, 0, 0, 1u8, 0, 0, 0, 0, 0, 0])
                    .await?;

                log::info!(
                    "Response sent to client for connection to {}",
                    target_address
                );

                // Now we can handle the data transfer between the client and the target address
                tokio::io::copy_bidirectional(&mut self.socket, &mut target_socket).await?;

                log::info!(
                    "Data transfer completed between client and target address: {}",
                    target_address
                );

                // Close the target socket
                target_socket.shutdown().await?;

                log::info!("Closed connection to target address: {}", target_address);

                self.close().await?;
            }
            Err(e) => {
                log::error!(
                    "Failed to connect to target address {}: {}",
                    target_address,
                    e
                );
                self.socket
                    .write_all(&[5, 1, 0, address_type.into(), 0, 0, 0, 0])
                    .await?;
                return Err(crate::errors::ServerError::ConnectionError(e.to_string()));
            }
        }

        Ok(())
    }

    pub async fn close(&mut self) -> crate::errors::Result<()> {
        self.socket.shutdown().await?;
        Ok(())
    }
}
