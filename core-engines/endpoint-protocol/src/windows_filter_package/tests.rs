use super::*;

#[test]
fn deployment_is_explicit_closed_and_does_not_relabel_package_bytes() {
    let (mut descriptor, bytes) = fixture(PROFILE);
    let old = serde_json::to_value(&descriptor).unwrap();
    assert!(old.get("deployment").is_none());
    assert!(serde_json::from_value::<Descriptor>(old.clone())
        .unwrap()
        .deployment
        .is_none());
    descriptor.deployment = Some(Deployment::InstallAndObserveDisarmedV1);
    let requested = serde_json::to_value(&descriptor).unwrap();
    assert_eq!(requested["deployment"], "install-and-observe-disarmed-v1");
    assert_eq!(
        descriptor.unpack(&bytes).unwrap()[1],
        descriptor.inf_bytes()
    );
    assert_eq!(requested["sha256"], old["sha256"]);
    for unsupported in [
        serde_json::json!(true),
        serde_json::json!("armed"),
        serde_json::json!({"load":true}),
    ] {
        let mut altered = requested.clone();
        altered["deployment"] = unsupported;
        assert!(serde_json::from_value::<Descriptor>(altered).is_err());
    }
}

fn fixture(profile: &str) -> (Descriptor, Vec<u8>) {
    let mut d = Descriptor {
        schema: 1,
        sha256: "a".repeat(64),
        bytes: 0,
        profile: profile.into(),
        trust_policy: TRUST.into(),
        source_revision: "b".repeat(40),
        expected_abi: 2,
        deployment: None,
        driver_version: "1.2.3.4".into(),
        driver_date: "02/29/2024".into(),
        altitude: "325000.01".into(),
        sys: Member {
            bytes: 256,
            sha256: "a".repeat(64),
        },
        inf: Member {
            bytes: 1,
            sha256: "a".repeat(64),
        },
        cat: Member {
            bytes: 1,
            sha256: "a".repeat(64),
        },
    };
    let mut sys = vec![0; 256];
    sys[..2].copy_from_slice(b"MZ");
    sys[60..64].copy_from_slice(&64u32.to_le_bytes());
    sys[64..70].copy_from_slice(b"PE\0\0\x64\x86");
    sys[88..90].copy_from_slice(&[11, 2]);
    sys[156..158].copy_from_slice(&[1, 0]);
    let inf = d.inf_bytes();
    let cat = b"unsigned structural fixture".to_vec();
    for (m, b) in [&mut d.sys, &mut d.inf, &mut d.cat]
        .into_iter()
        .zip([&sys, &inf, &cat])
    {
        m.bytes = b.len() as u64;
        m.sha256 = crate::hash(b);
    }
    let mut blob = MAGIC.to_vec();
    for m in d.members() {
        blob.extend(m.bytes.to_le_bytes());
    }
    for b in [&sys, &inf, &cat] {
        blob.extend(b);
    }
    d.bytes = blob.len() as u64;
    d.sha256 = crate::hash(&blob);
    (d, blob)
}
#[test]
fn exact_profiles_members_and_container_are_bound_without_load_claims() {
    for profile in [PROFILE, LEGACY_PROFILE] {
        let (d, bytes) = fixture(profile);
        d.validate().unwrap();
        let parts = d.unpack(&bytes).unwrap();
        assert_eq!(parts[1], d.inf_bytes());
        assert_eq!(
            String::from_utf8(d.inf_bytes())
                .unwrap()
                .contains("Parameters\\Instances"),
            profile == PROFILE
        );
        for n in [0, 7, 31, bytes.len() - 1] {
            assert!(d.unpack(&bytes[..n]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(d.unpack(&trailing).is_err());
        for at in [8, 32, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert!(d.unpack(&changed).is_err());
        }
        let mut other = d.clone();
        other.profile = if profile == PROFILE {
            LEGACY_PROFILE
        } else {
            PROFILE
        }
        .into();
        assert!(other.unpack(&bytes).is_err());
    }
}
#[test]
fn altitude_calendar_abi_policy_and_closed_metadata_refuse_ambiguity() {
    let (d, _) = fixture(PROFILE);
    for value in [
        "1",
        "319999",
        "330000",
        "325000.",
        "325000.1234567890",
        "0325000",
        "325000,foo",
    ] {
        let mut v = d.clone();
        v.altitude = value.into();
        assert!(v.validate().is_err(), "{value}");
    }
    for value in ["325000", "325000.0", "325000.00001"] {
        let mut v = d.clone();
        v.altitude = value.into();
        v.validate().unwrap();
    }
    for value in [
        "02/29/2023",
        "02/31/2024",
        "04/31/2025",
        "00/01/2025",
        "01/00/2025",
    ] {
        let mut v = d.clone();
        v.driver_date = value.into();
        assert!(v.validate().is_err());
    }
    let mut v = d.clone();
    v.expected_abi = 3;
    assert!(v.validate().is_err());
    v = d.clone();
    v.trust_policy = "generic-authenticode".into();
    assert!(v.validate().is_err());
    let mut json = serde_json::to_value(&d).unwrap();
    json["assigned_altitude"] = true.into();
    assert!(serde_json::from_value::<Descriptor>(json).is_err());
    let mut artifact = crate::installer::Artifact {
        target: "windows-x86_64".into(),
        version: "fixture".into(),
        sha256: "c".repeat(64),
        signing: "native-signature-verified".into(),
        native_adapter: None,
        macos_network: None,
        windows_filter: Some(d),
    };
    artifact.filter().unwrap();
    for target in ["linux-x86_64", "macos-aarch64"] {
        artifact.target = target.into();
        assert!(artifact.native().is_err());
        assert!(artifact.network().is_err());
    }
}
