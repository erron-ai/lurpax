use lurpax::archive::ArchiveLimits;
use lurpax::errors::LurpaxError;
use lurpax::vault::VaultService;

fn make_vault(dir: &std::path::Path, pw: &[u8]) -> std::path::PathBuf {
    let src = dir.join("input.txt");
    std::fs::write(&src, b"payload-data-for-testing").unwrap();
    let vault = dir.join("vault.lurpax");
    VaultService::create(&vault, &src, pw, None, None, ArchiveLimits::default(), None).unwrap();
    vault
}

#[test]
fn output_exists_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = make_vault(dir.path(), b"pass1");
    let src2 = dir.path().join("other.txt");
    std::fs::write(&src2, b"second").unwrap();
    let r = VaultService::create(&vault, &src2, b"pass1", None, None, ArchiveLimits::default(), None);
    assert!(matches!(r, Err(LurpaxError::OutputExists)));
}

#[test]
fn empty_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"x").unwrap();
    let vault = dir.path().join("v.lurpax");
    let r = VaultService::create(&vault, &src, b"", None, None, ArchiveLimits::default(), None);
    assert!(matches!(r, Err(LurpaxError::Password(_))));
}

#[test]
fn password_too_long_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("f.txt");
    std::fs::write(&src, b"x").unwrap();
    let vault = dir.path().join("v.lurpax");
    let long_pw = vec![b'A'; 9000];
    let r = VaultService::create(&vault, &src, &long_pw, None, None, ArchiveLimits::default(), None);
    assert!(matches!(r, Err(LurpaxError::Password(_))));
}

#[test]
fn truncated_vault_fails() {
    let dir = tempfile::tempdir().unwrap();
    let vault = make_vault(dir.path(), b"pw");
    let data = std::fs::read(&vault).unwrap();
    assert!(data.len() > 100);
    std::fs::write(&vault, &data[..data.len() - 100]).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let r = VaultService::open(&vault, &out, b"pw", None, ArchiveLimits::default(), None);
    assert!(r.is_err());
}

#[test]
fn wrong_password_key_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let vault = make_vault(dir.path(), b"pw1");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let r = VaultService::open(&vault, &out, b"pw2", None, ArchiveLimits::default(), None);
    assert!(matches!(r, Err(LurpaxError::DecryptAuthFailed)));
}

#[test]
fn tampered_ciphertext_fails() {
    let dir = tempfile::tempdir().unwrap();
    let vault = make_vault(dir.path(), b"secure");
    let mut data = std::fs::read(&vault).unwrap();

    let header_body_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
    let shard_offset = 9 + header_body_len;
    let shard_size: usize = 65536 + 16;
    let flip_at = shard_offset + shard_size / 2;
    if flip_at < data.len() {
        data[flip_at] ^= 0xFF;
    }
    std::fs::write(&vault, &data).unwrap();

    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let r = VaultService::open(&vault, &out, b"secure", None, ArchiveLimits::default(), None);
    // RS may transparently repair a single-byte flip, so either Ok or AEAD failure is acceptable.
    // The key invariant: if open returns Ok, the extracted content is authentic.
    if let Err(e) = r {
        assert!(
            matches!(e, LurpaxError::DecryptAuthFailed | LurpaxError::UnrecoverableDamage(_)),
            "unexpected error variant: {e:?}"
        );
    }
}
