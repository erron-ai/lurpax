//! End-to-end scenarios: many files, multi-chunk ciphertext, repair paths.
//!
//! Full 100GB-class runs are not executed in CI; these tests validate layout and
//! logic with raised limits. For production scale, also run manual soak tests.

use lurpax::archive::ArchiveLimits;
use lurpax::errors::VerifyHealth;
use lurpax::vault::header::{shard_cipher_size, total_shards};
use lurpax::vault::{Header, VaultService};
use std::fs;
use std::io::Write;

fn limits_for_scale() -> ArchiveLimits {
    ArchiveLimits {
        max_input_bytes: 512 * 1024 * 1024,
        max_files: 500,
        max_file_size: 256 * 1024 * 1024,
        max_output_bytes: 512 * 1024 * 1024,
    }
}

#[test]
fn e2e_many_files_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("many");
    fs::create_dir_all(&input).unwrap();
    let n = 180usize;
    for i in 0..n {
        let mut f = fs::File::create(input.join(format!("file_{i:04}.txt"))).unwrap();
        writeln!(f, "idx={i} pad={}", "x".repeat(64)).unwrap();
    }

    let vault = tmp.path().join("big_tree.lurpax");
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();

    VaultService::create(
        &vault,
        &input,
        b"e2e-many-files",
        None,
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();

    assert_eq!(VaultService::verify(&vault).unwrap(), VerifyHealth::Healthy);

    VaultService::open(
        &vault,
        &out,
        b"e2e-many-files",
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();

    let extracted = out.join("extracted");
    for i in 0..n {
        let p = extracted.join(format!("file_{i:04}.txt"));
        let got = fs::read_to_string(&p).unwrap();
        assert!(got.contains(&format!("idx={i}")), "file {i} mismatch");
    }
}

#[test]
fn e2e_multi_chunk_compressed_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("payload.bin");
    // High-entropy payload so zstd output stays > one 64KiB compressed chunk.
    let mut raw = vec![0u8; 180_000];
    getrandom::getrandom(&mut raw).unwrap();
    fs::write(&input, &raw).unwrap();

    let vault = tmp.path().join("multichunk.lurpax");
    let out = tmp.path().join("out_mc");
    fs::create_dir_all(&out).unwrap();

    VaultService::create(
        &vault,
        &input,
        b"multi-chunk-pass",
        None,
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();

    let vault_bytes = fs::read(&vault).unwrap();
    let hl = u32::from_le_bytes(vault_bytes[5..9].try_into().unwrap()) as usize;
    let header = Header::from_bytes_exact(&vault_bytes[9..9 + hl]).unwrap();
    assert!(
        header.chunk_count > 1,
        "expected >1 chunk for multi-chunk test, got {}",
        header.chunk_count
    );

    VaultService::open(
        &vault,
        &out,
        b"multi-chunk-pass",
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();

    let got = fs::read(out.join("extracted").join("payload.bin")).unwrap();
    assert_eq!(got, raw);
}

#[test]
fn e2e_corrupt_middle_shard_rs_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("blob.bin");
    fs::write(&input, vec![7u8; 120_000]).unwrap();

    let vault_path = tmp.path().join("repair_mid.lurpax");
    VaultService::create(
        &vault_path,
        &input,
        b"repair-secret",
        None,
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();

    let mut vault = fs::read(&vault_path).unwrap();
    let hl = u32::from_le_bytes(vault[5..9].try_into().unwrap()) as usize;
    let header = Header::from_bytes_exact(&vault[9..9 + hl]).unwrap();
    let ts = total_shards(&header).unwrap() as usize;
    let ss = shard_cipher_size(&header).unwrap() as usize;
    assert!(ts >= 4, "need RS layout");

    // Damage a middle data shard (not the first), not the last CRC-only region.
    let shard_area = 9 + hl;
    let target_shard = (ts / 3).max(1).min(ts - 2);
    let off = shard_area + target_shard * ss;
    for b in &mut vault[off..off + ss] {
        *b ^= 0x5c;
    }
    fs::write(&vault_path, &vault).unwrap();

    assert_eq!(
        VaultService::verify(&vault_path).unwrap(),
        VerifyHealth::Repairable
    );

    let out = tmp.path().join("out_repair");
    fs::create_dir_all(&out).unwrap();
    let repaired = VaultService::open(
        &vault_path,
        &out,
        b"repair-secret",
        None,
        limits_for_scale(),
        None,
    )
    .unwrap();
    assert!(repaired > 0);

    let got = fs::read(out.join("extracted").join("blob.bin")).unwrap();
    assert_eq!(got, vec![7u8; 120_000]);
}
