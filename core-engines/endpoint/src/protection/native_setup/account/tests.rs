use super::*;

#[derive(Default)]
struct Fixture {
    records: BTreeMap<String, Record>,
    ids: BTreeMap<(String, String), BTreeMap<String, u32>>,
    writes: usize,
    fail_after: Option<usize>,
    bad_lookup: bool,
}
impl Directory for Fixture {
    fn ids(&mut self, kind: &str, key: &str) -> Result<BTreeMap<String, u32>> {
        let mut values = self
            .ids
            .get(&(kind.into(), key.into()))
            .cloned()
            .unwrap_or_default();
        if let Some(v) = self
            .records
            .get(kind)
            .and_then(|r| r.get(key))
            .and_then(|v| v.first())
        {
            values.insert(NAME.into(), v.parse()?);
        }
        Ok(values)
    }
    fn record(&mut self, kind: &str) -> Result<Option<Record>> {
        Ok(self.records.get(kind).cloned())
    }
    fn set(&mut self, kind: &str, key: &str, value: &str) -> Result<()> {
        self.records
            .entry(kind.into())
            .or_default()
            .insert(key.into(), vec![value.into()]);
        self.writes += 1;
        if self.fail_after == Some(self.writes) {
            return Err("Simulated directory command interruption".into());
        }
        Ok(())
    }
    fn resolved(&mut self, _: u32, _: u32) -> Result<()> {
        if self.bad_lookup {
            Err("Simulated lookup/group mismatch".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn account_creation_avoids_used_ids_and_reuses_only_completed_owned_records() {
    let mut d = Fixture::default();
    d.ids.insert(
        ("Users".into(), "UniqueID".into()),
        BTreeMap::from([("other".into(), 499)]),
    );
    d.ids.insert(
        ("Users".into(), "PrimaryGroupID".into()),
        BTreeMap::from([("other".into(), 499)]),
    );
    d.ids.insert(
        ("Groups".into(), "PrimaryGroupID".into()),
        BTreeMap::from([("other".into(), 498)]),
    );
    let mut saves = vec![];
    let j = ensure(&mut d, None, "endpoint", |j| {
        saves.push(j.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!((j.uid, j.gid), (498, 497));
    assert!(!saves[0].complete && saves[1].complete);
    assert_eq!(
        d.records["Users"]["AuthenticationAuthority"],
        vec![";DisabledUser;"]
    );
    let count = d.writes;
    ensure(&mut d, Some(j), "endpoint", |_| {
        panic!("Completed account must not be changed")
    })
    .unwrap();
    assert_eq!(count, d.writes);
}
#[test]
fn interrupted_account_creation_resumes_the_original_generated_ids() {
    for boundary in 1..=expected(
        &Journal {
            schema: 1,
            endpoint_id: String::new(),
            uid: 499,
            gid: 499,
            user_uuid: String::new(),
            group_uuid: String::new(),
            complete: false,
        },
        "Users",
    )
    .len()
        + 3
    {
        let mut d = Fixture {
            fail_after: Some(boundary),
            ..Default::default()
        };
        let mut saved = None;
        assert!(ensure(&mut d, None, "endpoint", |j| {
            saved = Some(j.clone());
            Ok(())
        })
        .is_err());
        let original = saved.clone().unwrap();
        d.fail_after = None;
        let recovered = ensure(&mut d, saved, "endpoint", |_| Ok(())).unwrap();
        assert_eq!(original.user_uuid, recovered.user_uuid);
        assert_eq!(original.group_uuid, recovered.group_uuid);
        assert!(recovered.complete);
    }
}
#[test]
fn foreign_changed_shared_and_reassigned_accounts_are_never_repaired() {
    let mut foreign = Fixture::default();
    foreign.records.insert("Users".into(), Record::new());
    assert!(ensure(&mut foreign, None, "endpoint", |_| panic!(
        "Foreign account must not be claimed"
    ))
    .is_err());
    assert_eq!(foreign.writes, 0);
    for change in ["uuid", "shell", "member", "uid", "lookup"] {
        let mut d = Fixture::default();
        let j = ensure(&mut d, None, "endpoint", |_| Ok(())).unwrap();
        match change {
            "uuid" => {
                d.records
                    .get_mut("Users")
                    .unwrap()
                    .insert("GeneratedUID".into(), vec!["other".into()]);
            }
            "shell" => {
                d.records
                    .get_mut("Users")
                    .unwrap()
                    .insert("UserShell".into(), vec!["/bin/sh".into()]);
            }
            "member" => {
                d.records
                    .get_mut("Groups")
                    .unwrap()
                    .insert("GroupMembership".into(), vec!["other".into()]);
            }
            "uid" => {
                d.ids.insert(
                    ("Users".into(), "UniqueID".into()),
                    BTreeMap::from([("other".into(), j.uid)]),
                );
            }
            _ => d.bad_lookup = true,
        }
        let writes = d.writes;
        assert!(
            ensure(&mut d, Some(j), "endpoint", |_| panic!(
                "Changed account must not be claimed"
            ))
            .is_err(),
            "{change}"
        );
        assert_eq!(writes, d.writes, "{change}");
    }
}
#[test]
fn no_directory_mutation_occurs_if_intent_cannot_be_saved() {
    let mut d = Fixture::default();
    assert!(ensure(&mut d, None, "endpoint", |_| Err("Disk full".into())).is_err());
    assert_eq!(d.writes, 0);
}
#[test]
fn directory_attribute_decoder_rejects_wrong_types_and_ignores_secrets() {
    let r=parse_record(br#"{"dsAttrTypeStandard:GeneratedUID":["example"],"dsAttrTypeNative:ShadowHashData":["secret"]}"#).unwrap();
    assert_eq!(r.len(), 1);
    assert!(parse_record(br#"{"dsAttrTypeStandard:UniqueID":499}"#).is_err());
    assert!(parse_record(br#"{"dsAttrTypeStandard:UniqueID":[499]}"#).is_err());
}
