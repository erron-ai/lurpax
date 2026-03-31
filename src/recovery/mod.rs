//! Reed–Solomon repair and CRC-32C prechecks (accidental corruption only).

pub mod checksum;
pub mod fec;

pub use checksum::{build_checksum_table, verify_checksum_table};
pub use fec::{encode_rs_group, repair_group};
