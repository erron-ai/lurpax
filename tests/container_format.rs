use lurpax::archive::ArchiveLimits;
use lurpax::vault::VaultService;

fn create_vault(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("data.txt");
    std::fs::write(&src, b"format-test").unwrap();
    let vault = dir.join("v.lurpax");
    VaultService::create(&vault, &src, b"pw", None, None, ArchiveLimits::default(), None).unwrap();
    vault
}

#[test]
fn magic_bytes_correct() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let data = std::fs::read(&vault).unwrap();
    assert_eq!(&data[..5], b"LURPX");
}

#[test]
fn tail_magic_correct() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let data = std::fs::read(&vault).unwrap();
    assert_eq!(&data[data.len() - 5..], b"LURPX");
}

#[test]
fn tail_header_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let mut data = std::fs::read(&vault).unwrap();

    let header_body_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
    // Corrupt the primary header body (bytes 9..9+header_body_len) so primary parse fails.
    // Tail header copy remains intact, so open should succeed via fallback.
    let body_end = 9 + header_body_len;
    data[9..body_end].fill(0);
    std::fs::write(&vault, &data).unwrap();

    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    VaultService::open(&vault, &out, b"pw", None, ArchiveLimits::default(), None).unwrap();
    let got = std::fs::read(out.join("extracted").join("data.txt")).unwrap();
    assert_eq!(got, b"format-test");
}

#[test]
fn header_body_length_stored() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create_vault(dir.path());
    let data = std::fs::read(&vault).unwrap();
    let len = u32::from_le_bytes(data[5..9].try_into().unwrap());
    assert!(len > 0, "header body length must be positive");
    assert!(len < 4096, "header body length must be under MAX_HEADER_BODY_LEN");
}
