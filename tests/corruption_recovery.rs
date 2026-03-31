use std::fs;
use std::io::Write;
use std::path::Path;

use lurpax::archive::ArchiveLimits;
use lurpax::errors::VerifyHealth;
use lurpax::vault::header::{shard_cipher_size, total_shards};
use lurpax::vault::{Header, VaultService};

fn create_test_vault(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    let mut f = fs::File::create(input_dir.join("data.txt")).unwrap();
    f.write_all(b"lurpax corruption recovery test payload data\n")
        .unwrap();
    drop(f);

    let vault_path = dir.join("test.lurpax");
    VaultService::create(
        &vault_path,
        &input_dir,
        b"testpassword",
        None,
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();

    (vault_path, input_dir)
}

fn read_header_len(vault_bytes: &[u8]) -> u32 {
    u32::from_le_bytes(vault_bytes[5..9].try_into().unwrap())
}

#[test]
fn single_shard_corruption_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_path, input_dir) = create_test_vault(tmp.path());

    let original_content = fs::read_to_string(input_dir.join("data.txt")).unwrap();

    let mut vault = fs::read(&vault_path).unwrap();
    let header_len = read_header_len(&vault) as usize;
    let first_shard_offset = 9 + header_len;
    let shard_size = 65536 + 16;

    assert!(
        vault.len() > first_shard_offset + shard_size,
        "vault too small for corruption test"
    );
    for b in &mut vault[first_shard_offset..first_shard_offset + shard_size] {
        *b = 0;
    }
    fs::write(&vault_path, &vault).unwrap();

    let health = VaultService::verify(&vault_path).unwrap();
    assert_eq!(health, VerifyHealth::Repairable);

    let out_dir = tmp.path().join("output");
    let repaired = VaultService::open(
        &vault_path,
        &out_dir,
        b"testpassword",
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    assert!(repaired > 0, "should have repaired at least one shard");

    let recovered = fs::read_to_string(out_dir.join("extracted").join("data.txt")).unwrap();
    assert_eq!(recovered, original_content);
}

#[test]
fn checksum_table_corrupt_open_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let (vault_path, _) = create_test_vault(tmp.path());

    let mut vault = fs::read(&vault_path).unwrap();
    let header_len = read_header_len(&vault) as usize;
    let header_body = &vault[9..9 + header_len];
    let header = Header::from_bytes_exact(header_body).unwrap();
    let ts = total_shards(&header).unwrap() as usize;
    let ss = shard_cipher_size(&header).unwrap() as usize;
    let shard_area_start = 9 + header_len;
    let crc_start = shard_area_start + ts * ss;
    assert!(
        crc_start + 8 <= vault.len(),
        "CRC region must fit; vault len {}",
        vault.len()
    );

    // Corrupt two CRC slots (8 bytes) → two false "damaged" flags; RS parity is 3 per group.
    for b in &mut vault[crc_start..crc_start + 8] {
        *b ^= 0xFF;
    }
    fs::write(&vault_path, &vault).unwrap();

    let out_dir = tmp.path().join("output_fallback");
    let result = VaultService::open(
        &vault_path,
        &out_dir,
        b"testpassword",
        None,
        ArchiveLimits::default(),
        None,
    );
    assert!(
        result.is_ok(),
        "open should succeed via CRC-triggered RS repair: {result:?}"
    );
}
