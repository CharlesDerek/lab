use athernex_endpoint::managed_engine;
use athernex_endpoint_protocol::{
    self as p,
    engine::{File, Release, Roles, SignedRelease},
};
#[test]
fn publication_copies_only_verified_members_and_never_replaces_release_or_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    let paths = [
        "bin/clamscan",
        "bin/freshclam",
        "sbin/clamd",
        "sbin/clamonacc",
        "lib/libfixture.so",
        "etc/certs/fixture.crt",
    ];
    let files = paths
        .iter()
        .map(|path| {
            let file = source.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, path.as_bytes()).unwrap();
            File {
                path: (*path).into(),
                sha256: p::hash(path.as_bytes()),
                bytes: path.len() as u64,
                executable: path.starts_with("bin/") || path.starts_with("sbin/"),
            }
        })
        .collect();
    std::fs::write(source.join("not-in-manifest"), b"must not publish").unwrap();
    let (private, key) = p::update::generate_key().unwrap();
    let now = athernex_endpoint::now_ms();
    let release = SignedRelease::sign(
        Release {
            schema: 1,
            protocol: p::PROTOCOL,
            engine: "clamav".into(),
            target: "linux-x86_64".into(),
            version: "fixture".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: now,
            expires_ms: now + 600000,
            roles: Roles {
                scanner: paths[0].into(),
                updater: paths[1].into(),
                daemon: paths[2].into(),
                monitor: Some(paths[3].into()),
                library_dirs: vec!["lib".into()],
                certificates: "etc/certs".into(),
            },
            files,
        },
        &private,
    )
    .unwrap();
    let manifest = root.join("manifest.json");
    std::fs::write(&manifest, serde_json::to_vec(&release).unwrap()).unwrap();
    let catalog = root.join("catalog");
    let id = managed_engine::publish(&manifest, &source, &key, &catalog).unwrap();
    assert_eq!(id, release.id().unwrap());
    assert!(!catalog.join(&id).join("content/not-in-manifest").exists());
    assert!(managed_engine::publish(&manifest, &source, &key, &catalog).is_err());
    let (_, wrong) = p::update::generate_key().unwrap();
    assert!(managed_engine::publish(&manifest, &source, &wrong, &root.join("wrong")).is_err());
    std::fs::write(source.join(paths[0]), b"tampered").unwrap();
    assert!(managed_engine::publish(&manifest, &source, &key, &root.join("tampered")).is_err());
    assert_eq!(
        std::fs::read(catalog.join(&id).join("content").join(paths[0])).unwrap(),
        paths[0].as_bytes()
    );
}
