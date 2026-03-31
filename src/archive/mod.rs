//! Tar snapshot creation and hardened extraction.

pub mod tar;

pub use tar::{ArchiveLimits, extract_tar, tar_input};
