use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The specified interface does not exist")]
    InvalidInterface,
    #[error("Failed to find host IPv4 address")]
    NoIpv4,
}
