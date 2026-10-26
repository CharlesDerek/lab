use super::*;
use std::io::Write;
fn fixture() -> (Tree, MacosNetworkArtifact) {
    let mut executable = vec![0u8; 64];
    executable[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    executable[4..8].copy_from_slice(&0x100000cu32.to_le_bytes());
    let mut a = MacosNetworkArtifact {
        schema: 1,
        backend: "macos-network-extension".into(),
        signing: "native-signature-verified".into(),
        sha256: "a".repeat(64),
        bytes: 1,
        tree_sha256: "b".repeat(64),
        container_sha256: protocol::hash(&executable),
        provider_sha256: protocol::hash(&executable),
        source_policy_sha256: protocol::macos_network_events::source_policy_sha256(),
        team_id: "ABCDE12345".into(),
        agent_identifier: "invalid.example.agent".into(),
        container_identifier: "invalid.example.container".into(),
        provider_identifier: "invalid.example.provider".into(),
        app_group: "ABCDE12345.invalid.example.group".into(),
        mach_service_name: "ABCDE12345.invalid.example.group.telemetry".into(),
        provider_cdhashes: vec!["a".repeat(40)],
    };
    let mut tree = Tree::new();
    for prefix in [APP.to_string(), provider_prefix(&a)] {
        tree.insert(
            format!("{prefix}/Contents/Info.plist"),
            (0o644, b"synthetic unsigned plist".to_vec()),
        );
    }
    tree.insert(
        format!("{APP}/Contents/MacOS/AthernexNetwork"),
        (0o755, executable.clone()),
    );
    tree.insert(
        format!(
            "{}/Contents/MacOS/AthernexNetworkProvider",
            provider_prefix(&a)
        ),
        (0o755, executable),
    );
    a.tree_sha256 = tree_digest(&tree);
    (tree, a)
}
fn archive(tree: &Tree, a: &mut MacosNetworkArtifact) -> Vec<u8> {
    archive_for_system(tree, a, zip::System::Unix)
}
fn archive_for_system(tree: &Tree, a: &mut MacosNetworkArtifact, system: zip::System) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, (mode, bytes)) in tree {
        writer
            .start_file(
                path,
                zip::write::SimpleFileOptions::default()
                    .system(system)
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(*mode),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    a.bytes = bytes.len() as u64;
    a.sha256 = protocol::hash(&bytes);
    bytes
}
#[test]
fn exact_archive_modes_architecture_and_tree_are_bound() {
    let (tree, mut a) = fixture();
    let bytes = archive(&tree, &mut a);
    assert_eq!(unpack(&bytes, &a, "macos-aarch64").unwrap(), tree);
    assert!(unpack(&bytes, &a, "macos-x86_64").is_err());
    let mut changed = bytes.clone();
    changed[40] ^= 1;
    assert!(unpack(&changed, &a, "macos-aarch64").is_err());
    a.tree_sha256 = "f".repeat(64);
    assert!(unpack(&bytes, &a, "macos-aarch64").is_err());
}
#[test]
fn dos_creator_cannot_substitute_for_unix_permission_semantics() {
    let (tree, mut artifact) = fixture();
    let bytes = archive_for_system(&tree, &mut artifact, zip::System::Dos);
    assert!(unpack(&bytes, &artifact, "macos-aarch64")
        .unwrap_err()
        .to_string()
        .contains("central entry"));
}
#[test]
fn traversal_unexpected_profiles_and_writeable_modes_are_refused_before_extraction() {
    for path in ["../outside", "AthernexNetwork.app/Contents/Resources/raw-network.log", "AthernexNetwork.app/Contents/Library/SystemExtensions/other.systemextension/Contents/Info.plist"] {
        let(mut tree,mut a)=fixture();tree.insert(path.into(),(0o644,b"private fixture".to_vec()));a.tree_sha256=tree_digest(&tree);let bytes=archive(&tree,&mut a);assert!(unpack(&bytes,&a,"macos-aarch64").is_err());
    }
    let (mut tree, mut a) = fixture();
    tree.get_mut(&format!("{APP}/Contents/Info.plist"))
        .unwrap()
        .0 = 0o666;
    a.tree_sha256 = tree_digest(&tree);
    let bytes = archive(&tree, &mut a);
    assert!(unpack(&bytes, &a, "macos-aarch64").is_err());
}
#[test]
fn component_requires_closed_role_policy_and_sorted_code_hashes() {
    let (_, a) = fixture();
    a.validate().unwrap();
    let mut bad = a.clone();
    bad.provider_identifier = "invalid.example.provider\" or true".into();
    assert!(bad.validate().is_err());
    let mut bad = a.clone();
    bad.provider_cdhashes.push(bad.provider_cdhashes[0].clone());
    assert!(bad.validate().is_err());
    let mut bad = a.clone();
    bad.source_policy_sha256 = "e".repeat(64);
    assert!(bad.validate().is_err());
    let mut value = serde_json::to_value(a).unwrap();
    value["raw_requirement"] = "true".into();
    assert!(serde_json::from_value::<MacosNetworkArtifact>(value).is_err());
}
#[test]
fn deployment_never_accepts_an_arbitrary_installed_path_or_enables_legacy_policy() {
    let (_, a) = fixture();
    let mut d = Deployment {
        path: INSTALL_PATH.into(),
        target: "macos-aarch64".into(),
        artifact: a,
    };
    d.validate().unwrap();
    d.path = "/tmp/AthernexNetwork.app".into();
    assert!(d.validate().is_err());
    let legacy = serde_json::json!({"enabled":false,"interval_secs":30});
    let policy: crate::telemetry::TelemetryConfig = serde_json::from_value(legacy).unwrap();
    assert!(!policy.macos_network_events);
    assert!(policy.macos_network_deployment.is_none());
    assert!(serde_json::to_value(policy)
        .unwrap()
        .get("macos_network_events")
        .is_none());
}

#[test]
fn oversized_directory_or_comment_is_refused_before_zip_metadata_allocation() {
    let (tree, mut artifact) = fixture();
    let original = archive(&tree, &mut artifact);
    for offset in [8, 10, 20] {
        let mut bytes = original.clone();
        let i = bytes.len() - 22 + offset;
        bytes[i..i + 2].copy_from_slice(&513u16.to_le_bytes());
        artifact.sha256 = protocol::hash(&bytes);
        let error = unpack(&bytes, &artifact, "macos-aarch64")
            .unwrap_err()
            .to_string();
        assert!(error.contains("finite format"));
    }
}

#[test]
fn declared_component_requires_exact_marker_and_archive_even_when_both_disappear() {
    let dir = tempfile::tempdir().unwrap();
    let (tree, mut component) = fixture();
    let bytes = archive(&tree, &mut component);
    let mut artifact = Artifact {
        windows_filter: None,
        target: "macos-aarch64".into(),
        version: "fixture".into(),
        sha256: "e".repeat(64),
        signing: "native-signature-verified".into(),
        native_adapter: None,
        macos_network: Some(component),
    };
    assert!(check_declared_components(&artifact, dir.path()).is_err());
    std::fs::write(dir.path().join("macos-network.required"), b"1\n").unwrap();
    assert!(check_declared_components(&artifact, dir.path()).is_err());
    std::fs::write(dir.path().join("macos-network.zip"), &bytes).unwrap();
    check_declared_components(&artifact, dir.path()).unwrap();
    std::fs::write(dir.path().join("macos-network.required"), b"2\n").unwrap();
    assert!(check_declared_components(&artifact, dir.path()).is_err());
    std::fs::write(dir.path().join("macos-network.required"), b"1\n").unwrap();
    std::fs::write(
        dir.path().join("macos-network.zip"),
        b"changed after snapshot",
    )
    .unwrap();
    check_declared_components(&artifact, dir.path()).unwrap();
    artifact.macos_network = None;
    assert!(check_declared_components(&artifact, dir.path()).is_err());
    std::fs::remove_file(dir.path().join("macos-network.required")).unwrap();
    std::fs::remove_file(dir.path().join("macos-network.zip")).unwrap();
    check_declared_components(&artifact, dir.path()).unwrap();
}

#[test]
fn malformed_final_directory_cannot_fall_back_to_an_embedded_earlier_archive() {
    let (tree, mut artifact) = fixture();
    let mut bytes = archive(&tree, &mut artifact);
    let offset = bytes.len() as u32;
    bytes.extend_from_slice(&[0u8; 46]);
    let mut footer = [0u8; 22];
    footer[..4].copy_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    footer[8..10].copy_from_slice(&1u16.to_le_bytes());
    footer[10..12].copy_from_slice(&1u16.to_le_bytes());
    footer[12..16].copy_from_slice(&46u32.to_le_bytes());
    footer[16..20].copy_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&footer);
    artifact.bytes = bytes.len() as u64;
    artifact.sha256 = protocol::hash(&bytes);
    assert!(unpack(&bytes, &artifact, "macos-aarch64")
        .unwrap_err()
        .to_string()
        .contains("central entry"));
}
