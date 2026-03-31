//! End-to-end create / open / verify.

use lurpax::archive::ArchiveLimits;
use lurpax::errors::VerifyHealth;
use lurpax::vault::VaultService;

#[test]
fn create_open_roundtrip_file() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("note.txt");
    std::fs::write(&src, b"confidential").unwrap();
    let vault = dir.path().join("vault.lurpax");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    VaultService::create(
        &vault,
        &src,
        b"correct-horse",
        None,
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    VaultService::open(
        &vault,
        &out,
        b"correct-horse",
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    let got = std::fs::read(out.join("extracted").join("note.txt")).unwrap();
    assert_eq!(got, b"confidential");
}

#[test]
fn verify_healthy_vault() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a");
    std::fs::write(&src, b"x").unwrap();
    let vault = dir.path().join("v.lurpax");
    VaultService::create(
        &vault,
        &src,
        b"p",
        None,
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    let h = VaultService::verify(&vault).unwrap();
    assert_eq!(h, VerifyHealth::Healthy);
}

#[test]
fn open_wrong_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a");
    std::fs::write(&src, b"x").unwrap();
    let vault = dir.path().join("v.lurpax");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    VaultService::create(
        &vault,
        &src,
        b"good",
        None,
        None,
        ArchiveLimits::default(),
        None,
    )
    .unwrap();
    let r = VaultService::open(&vault, &out, b"bad", None, ArchiveLimits::default(), None);
    assert!(r.is_err());
}
