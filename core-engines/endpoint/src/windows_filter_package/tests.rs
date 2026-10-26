use super::*;
fn descriptor() -> Descriptor {
    Descriptor {
        schema: 1,
        sha256: "a".repeat(64),
        bytes: 289,
        profile: protocol::windows_filter_package::PROFILE.into(),
        trust_policy: protocol::windows_filter_package::TRUST.into(),
        source_revision: "b".repeat(40),
        expected_abi: 2,
        driver_version: "1.2.3.4".into(),
        driver_date: "01/01/2025".into(),
        altitude: "325000.01".into(),
        sys: protocol::windows_filter_package::Member {
            bytes: 256,
            sha256: "c".repeat(64),
        },
        inf: protocol::windows_filter_package::Member {
            bytes: 1,
            sha256: "d".repeat(64),
        },
        cat: protocol::windows_filter_package::Member {
            bytes: 0,
            sha256: "e".repeat(64),
        },
    }
}
#[test]
fn preparation_never_commits_unknown_members_or_rebinds_incomplete_release() {
    let mut d = descriptor();
    d.cat.bytes = 1;
    d.bytes = 290;
    let mut r = Preparation {
        schema: 1,
        transaction: "f".repeat(64),
        source_sha256: "1".repeat(64),
        descriptor: d.clone(),
        state_volume: 1,
        state_file_id: [2; 16],
        directory: None,
        prepared: false,
        members: [None; 4],
    };
    r.validate().unwrap();
    r.matches(&"1".repeat(64), &d).unwrap();
    assert!(r.matches(&"2".repeat(64), &d).is_err());
    r.prepared = true;
    assert!(r.validate().is_err());
    r.directory = Some((1, [3; 16]));
    assert!(r.validate().is_err());
    r.members = [Some((1, [4; 16])); 4];
    r.validate().unwrap();
    r.matches(&"2".repeat(64), &d).unwrap();
    let mut changed = d.clone();
    changed.expected_abi = 3;
    assert!(r.matches(&r.source_sha256, &changed).is_err());
    changed = d.clone();
    changed.cat.sha256 = "9".repeat(64);
    assert!(r.matches(&r.source_sha256, &changed).is_err());
}
#[test]
fn undeclared_component_and_unsupported_platform_cannot_be_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = Artifact {
        target: protocol::update::target(),
        version: "fixture".into(),
        sha256: "a".repeat(64),
        signing: "native-signature-verified".into(),
        native_adapter: None,
        macos_network: None,
        windows_filter: None,
    };
    components(temp.path(), &a).unwrap();
    std::fs::write(temp.path().join("windows-filter.required"), b"1\n").unwrap();
    assert!(components(temp.path(), &a).is_err());
    let mut d = descriptor();
    d.cat.bytes = 1;
    d.bytes = 290;
    a.windows_filter = Some(d);
    a.target = "linux-x86_64".into();
    assert!(components(temp.path(), &a).is_err());
}

#[test]
fn journal_boundaries_refuse_unrecorded_creation_and_replay_only_exact_members() {
    let mut d = descriptor();
    d.cat.bytes = 1;
    d.bytes = 290;
    let mut r = Preparation {
        schema: 1,
        transaction: "f".repeat(64),
        source_sha256: "1".repeat(64),
        descriptor: d,
        state_volume: 1,
        state_file_id: [2; 16],
        directory: Some((1, [3; 16])),
        prepared: false,
        members: [None; 4],
    };
    for index in 0..4 {
        let id = (1, [10 + index as u8; 16]);
        assert!(r.member_action(index, None).unwrap());
        assert!(r.member_action(index, Some(id)).is_err()); // creation before identity receipt: never adopt
        r.members[index] = Some(id);
        assert!(!r.member_action(index, Some(id)).unwrap()); // durable identity, crash before next member
        assert!(r.member_action(index, None).is_err());
        assert!(r.member_action(index, Some((1, [99; 16]))).is_err());
    }
    r.prepared = true;
    r.validate().unwrap();
    for index in 0..4 {
        assert!(!r.member_action(index, r.members[index]).unwrap());
        assert!(r.member_action(index, None).is_err());
    }
}

#[cfg(unix)]
#[test]
fn dangling_required_component_is_not_treated_as_absent() {
    let temp = tempfile::tempdir().unwrap();
    let artifact = Artifact {
        target: protocol::update::target(),
        version: "fixture".into(),
        sha256: "a".repeat(64),
        signing: "development-unsigned".into(),
        native_adapter: None,
        macos_network: None,
        windows_filter: None,
    };
    std::os::unix::fs::symlink(
        temp.path().join("missing"),
        temp.path().join("windows-filter.required"),
    )
    .unwrap();
    assert!(components(temp.path(), &artifact).is_err());
}
#[test]
fn public_capability_errors_do_not_echo_unknown_metadata_or_paths() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-release.json");
    std::fs::write(&path, b"{bad private metadata}").unwrap();
    assert_eq!(
        installer_hash(&path).unwrap_err().to_string(),
        "Windows driver component capability refused"
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        installer_hash(&path).unwrap_err().to_string(),
        "Windows driver component capability refused"
    );
}

#[test]
fn pre_stop_installer_check_does_not_echo_unknown_driver_descriptor_fields() {
    let temp = tempfile::tempdir().unwrap();
    let mut d = descriptor();
    d.cat.bytes = 1;
    d.bytes = 290;
    let mut value = serde_json::to_value(d).unwrap();
    value["private-account-marker"] = serde_json::json!("private payload");
    let artifact = serde_json::json!({"target":"windows-x86_64","version":"0.1.0","sha256":"a".repeat(64),"signing":"native-signature-verified","windows_filter":value});
    std::fs::write(
        temp.path().join("release.json"),
        serde_json::to_vec(&artifact).unwrap(),
    )
    .unwrap();
    assert_eq!(
        crate::macos_network_bundle::installer_components(&temp.path().join("endpoint.exe"))
            .unwrap_err()
            .to_string(),
        "Installer component metadata refused"
    );
}
