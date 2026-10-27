//! Security tests for path confinement
//! Tests cover traversal, symlinks, absolute paths, and edge cases

#[cfg(test)]
mod security {
    use vak_sandbox_core::path::{confined, is_contained, safe_canonicalize};
    use std::fs;
    use std::os::unix::fs as unix_fs;
    use tempfile::TempDir;

    #[test]
    fn reject_parent_traversal_variants() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        assert!(confined(root, "../etc/passwd").is_err());
        assert!(confined(root, "../../etc/passwd").is_err());
        assert!(confined(root, "foo/../../etc/passwd").is_err());
        assert!(confined(root, "./../etc/passwd").is_err());
        assert!(confined(root, "foo/../bar/../../etc/passwd").is_err());
    }

    #[test]
    fn reject_absolute_paths() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        assert!(confined(root, "/etc/passwd").is_err());
        assert!(confined(root, "/tmp/foo").is_err());
        assert!(confined(root, "/").is_err());
    }

    #[test]
    fn allow_normal_relative_paths() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        assert!(confined(root, "file.txt").is_ok());
        assert!(confined(root, "src/main.rs").is_ok());
        assert!(confined(root, "a/b/c/d/e.txt").is_ok());
        assert!(confined(root, "./file.txt").is_ok());
    }

    #[test]
    fn reject_symlink_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let outside = tmp.path().parent().unwrap().join("outside_test");
        let _ = fs::create_dir_all(&outside);
        let link = root.join("badlink");
        let _ = unix_fs::symlink(&outside, &link);
        // Creating a path through symlink should be rejected
        let result = confined(root, "badlink/file.txt");
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn is_contained_validates() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let inside = root.join("test.txt");
        fs::write(&inside, "hi").unwrap();
        assert!(is_contained(&root, &inside).unwrap());
        let outside = std::env::temp_dir().join("outside_12345.txt");
        fs::write(&outside, "hi").unwrap();
        assert!(!is_contained(&root, &outside).unwrap());
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn safe_canonicalize_rejects_escape() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let outside = std::env::temp_dir().canonicalize().unwrap().join("x.txt");
        let _ = fs::write(&outside, "hi");
        assert!(safe_canonicalize(&root, &outside).is_err());
        let _ = fs::remove_file(&outside);
    }
}
