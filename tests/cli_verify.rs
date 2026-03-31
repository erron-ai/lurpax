use lurpax::archive::ArchiveLimits;
use lurpax::errors::VerifyHealth;
use lurpax::vault::VaultService;

const SHARD_SIZE: usize = 65536 + 16; // chunk_plaintext_size + Poly1305 tag

fn create_vault(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("data.txt");
    std::fs::write(&src, b"verify-test-payload").unwrap();
    let vault = dir.join("v.lurpax");
    VaultService::create(
        &vault,
        &src,
        b"pw",
        None,
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    vault
}

fn shard_data_offset(data: &[u8]) -> usize {
    let header_body_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
    9 + header_body_len
}

#[test]
fn verify_healthy_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let h = VaultService::verify(&vault).unwrap();
    assert_eq!(h, VerifyHealth::Healthy);
    assert_eq!(h.exit_code(), 0);
}

#[test]
fn verify_repairable_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let mut data = std::fs::read(&vault).unwrap();

    let base = shard_data_offset(&data);
    // Corrupt one data shard (flip several bytes in the middle)
    for i in 0..64 {
        let pos = base + SHARD_SIZE / 2 + i;
        if pos < data.len() {
            data[pos] ^= 0xFF;
        }
    }
    std::fs::write(&vault, &data).unwrap();

    let h = VaultService::verify(&vault).unwrap();
    assert_eq!(h, VerifyHealth::Repairable);
    assert_eq!(h.exit_code(), 1);
}

#[test]
fn verify_unrecoverable_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let mut data = std::fs::read(&vault).unwrap();

    let base = shard_data_offset(&data);
    // Corrupt 4 consecutive shards (exceeds RS parity=3 within one group)
    for shard_idx in 0..4 {
        let start = base + shard_idx * SHARD_SIZE;
        let end = start + SHARD_SIZE;
        if end <= data.len() {
            data[start..end].fill(0);
        }
    }
    std::fs::write(&vault, &data).unwrap();

    let h = VaultService::verify(&vault).unwrap();
    assert_eq!(h, VerifyHealth::Unrecoverable);
    assert_eq!(h.exit_code(), 2);
}
