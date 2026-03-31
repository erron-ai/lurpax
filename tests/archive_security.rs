//! Archive path-safety and limit enforcement tests.

use std::fs;
use std::io::Write;

use lurpax::archive::{extract_tar, tar_input, ArchiveLimits};
use lurpax::LurpaxError;

#[test]
fn symlink_in_source_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.txt");
    fs::write(&target, b"hello").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, dir.path().join("link.txt")).unwrap();
    #[cfg(not(unix))]
    {
        // Symlink creation requires elevated privileges on Windows; skip.
        return;
    }
    let err = tar_input(dir.path(), &ArchiveLimits::default()).unwrap_err();
    assert!(matches!(err, LurpaxError::UnsafeArchive(_)));
}

#[test]
fn file_too_large_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big.bin");
    {
        let mut f = fs::File::create(&big).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
    }
    let limits = ArchiveLimits {
        max_file_size: 10,
        ..Default::default()
    };
    let err = tar_input(&big, &limits).unwrap_err();
    assert!(matches!(err, LurpaxError::LimitExceeded(_)));
}

#[test]
fn too_many_files_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
    }
    let limits = ArchiveLimits {
        max_files: 2,
        ..Default::default()
    };
    let err = tar_input(dir.path(), &limits).unwrap_err();
    assert!(matches!(err, LurpaxError::LimitExceeded(_)));
}

#[test]
fn extract_unsafe_path_component() {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let mut header = tar::Header::new_gnu();
        // `set_path` rejects `..`; write the traversal path into raw name bytes.
        let name = b"../escape.txt\0";
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"evil" as &[u8]).unwrap();
        builder.finish().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let err = extract_tar(buf.as_slice(), dir.path(), &ArchiveLimits::default()).unwrap_err();
    assert!(matches!(err, LurpaxError::UnsafeArchive(_)));
}

#[test]
fn extract_unsupported_entry_type() {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("link.txt").unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header
            .set_link_name("target.txt")
            .unwrap();
        header.set_cksum();
        builder.append(&header, &[] as &[u8]).unwrap();
        builder.finish().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let err = extract_tar(buf.as_slice(), dir.path(), &ArchiveLimits::default()).unwrap_err();
    assert!(matches!(err, LurpaxError::UnsafeArchive(_)));
}

#[test]
fn special_file_in_source_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.txt");
    fs::write(&target, b"data").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, dir.path().join("sym")).unwrap();
    #[cfg(not(unix))]
    {
        return;
    }
    let err = tar_input(dir.path(), &ArchiveLimits::default()).unwrap_err();
    assert!(matches!(err, LurpaxError::UnsafeArchive(_)));
}
