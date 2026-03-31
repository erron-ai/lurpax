//! Tar snapshot creation and hardened extraction.

pub mod tar;

pub use tar::{extract_tar, tar_input, ArchiveLimits};
