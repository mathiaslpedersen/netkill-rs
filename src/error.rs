use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The specified interface does not exist")]
    InvalidInterface,
    #[error("Failed to find host IPv4 address")]
    NoIpv4,
    #[error("Failed to open datalink channel. Are you root?")]
    OpenChannel {
        source: std::io::Error
    },
}
