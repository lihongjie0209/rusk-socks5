
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {

    #[error("Failed to bind to address: {0}")]
    BindError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid request format")]
    InvalidRequestFormat,

    #[error("Unsupported protocol version")]
    UnsupportedProtocolVersion,

    #[error("Unsupported command: {0}")]
    UnsupportedCmd(u8),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Unknown error occurred: {0}")]
    Unknown(String),


}


pub type Result<T> = std::result::Result<T, ServerError>;