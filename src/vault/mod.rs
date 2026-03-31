//! Vault container format: header, shards, checksum table, tail header.

pub mod container;
pub mod header;
pub mod service;

pub use container::VaultLayout;
pub use header::Header;
pub use service::VaultService;
