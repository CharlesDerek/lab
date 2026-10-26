use super::*;

fn entry(path: &str, inode: u64, kind: Kind) -> Entry {
    let mode = if path.is_empty() {
        0o700
    } else if kind == Kind::Directory {
        0o755
    } else {
        0o644
    };
    Entry {
        path: path.to_owned(),
        identity: ObjectId { device: 1, inode },
        mode,
        kind,
    }
}
fn file(size: u64) -> Kind {
    Kind::File {
        size,
        sha256: "a".repeat(64),
    }
}
fn plan() -> Plan {
    Plan {
        schema: 1,
        transaction_id: "b".repeat(64),
        ledger_sha256: "c".repeat(64),
        provider_identifier: "com.example.network.provider".into(),
        entries: vec![
            entry("AthernexNetwork.app/Contents/Info.plist", 4, file(10)),
            entry("AthernexNetwork.app/Contents", 3, Kind::Directory),
            entry("AthernexNetwork.app", 2, Kind::Directory),
            entry("upgrade-service.plist", 5, file(20)),
            entry("", 1, Kind::Directory),
        ],
    }
}
#[derive(Clone)]
struct Model {
    entries: BTreeMap<String, Entry>,
    removed: Vec<String>,
    syncs: Vec<String>,
    fail_remove: Option<usize>,
    fail_sync: Option<usize>,
    replace_on_remove: Option<String>,
}
impl Model {
    fn new(plan: &Plan) -> Self {
        Self {
            entries: plan
                .entries
                .iter()
                .cloned()
                .map(|e| (e.path.clone(), e))
                .collect(),
            removed: Vec::new(),
            syncs: Vec::new(),
            fail_remove: None,
            fail_sync: None,
            replace_on_remove: None,
        }
    }
}
impl TreeOps for Model {
    fn inventory(&mut self) -> Result<Vec<Entry>> {
        Ok(self.entries.values().cloned().collect())
    }
    fn remove(&mut self, expected: &Entry, plan: &Plan) -> Result<()> {
        if self.fail_remove == Some(self.removed.len()) {
            return Err("Injected removal failure".into());
        }
        if self.replace_on_remove.as_deref() == Some(expected.path.as_str()) {
            self.entries.get_mut(&expected.path).unwrap().identity.inode += 100;
            self.replace_on_remove = None;
        }
        let Some(actual) = self.entries.get(&expected.path) else {
            return Ok(());
        };
        if actual != expected {
            return Err("Changed object refused".into());
        }
        let mut ancestor = parent(&expected.path);
        while let Some(path) = ancestor {
            let recorded = plan.entries.iter().find(|e| e.path == path).unwrap();
            if self.entries.get(path) != Some(recorded) {
                return Err("Changed parent refused".into());
            }
            ancestor = parent(path);
        }
        if expected.kind == Kind::Directory
            && self
                .entries
                .keys()
                .any(|p| parent(p) == Some(expected.path.as_str()))
        {
            return Err("Directory has children".into());
        }
        self.entries.remove(&expected.path);
        self.removed.push(expected.path.clone());
        Ok(())
    }
    fn sync_parent(&mut self, path: &str, _: &Plan) -> Result<()> {
        if self.fail_sync == Some(self.syncs.len()) {
            return Err("Injected parent sync failure".into());
        }
        self.syncs.push(path.to_owned());
        Ok(())
    }
}

#[test]
fn exact_postorder_removes_only_planned_objects_and_syncs_every_parent() {
    let plan = plan();
    let mut model = Model::new(&plan);
    cleanup(&plan, &mut model).unwrap();
    let paths: Vec<_> = plan.entries.iter().map(|e| e.path.clone()).collect();
    assert_eq!(model.removed, paths);
    assert_eq!(model.syncs, paths);
    assert!(model.entries.is_empty());
    // Replay still syncs the existing containing namespace after root removal.
    model.syncs.clear();
    cleanup(&plan, &mut model).unwrap();
    assert_eq!(model.removed, paths);
    assert_eq!(model.syncs, paths);
}

#[test]
fn every_partial_remove_or_sync_failure_resumes_without_adopting_objects() {
    let plan = plan();
    for at in 0..plan.entries.len() {
        for sync in [false, true] {
            let mut model = Model::new(&plan);
            if sync {
                model.fail_sync = Some(at);
            } else {
                model.fail_remove = Some(at);
            }
            assert!(cleanup(&plan, &mut model).is_err());
            let expected_removed = at + usize::from(sync);
            assert_eq!(model.removed.len(), expected_removed);
            model.fail_remove = None;
            model.fail_sync = None;
            model.syncs.clear();
            cleanup(&plan, &mut model).unwrap();
            assert_eq!(model.removed.len(), plan.entries.len());
            assert_eq!(
                model.syncs,
                plan.entries
                    .iter()
                    .map(|e| e.path.clone())
                    .collect::<Vec<_>>()
            );
            assert!(model.entries.is_empty());
        }
    }
}

#[test]
fn unknown_changed_or_detached_objects_refuse_before_any_removal() {
    let plan = plan();
    for variant in 0..7 {
        let mut model = Model::new(&plan);
        let target = &plan.entries[0].path;
        match variant {
            0 => {
                model
                    .entries
                    .insert("foreign".into(), entry("foreign", 77, file(1)));
            }
            1 => model.entries.get_mut(target).unwrap().identity.inode += 1,
            2 => model.entries.get_mut(target).unwrap().mode = 0o600,
            3 => model.entries.get_mut(target).unwrap().kind = file(11),
            4 => model.entries.get_mut(target).unwrap().kind = Kind::Directory,
            5 => {
                model.entries.remove("AthernexNetwork.app/Contents");
            }
            _ => model.entries.get_mut("").unwrap().identity.device += 1,
        }
        assert!(cleanup(&plan, &mut model).is_err());
        assert!(model.removed.is_empty());
    }
}

#[test]
fn changed_entry_after_inventory_is_refused_by_removal_adapter() {
    let plan = plan();
    let mut model = Model::new(&plan);
    model.replace_on_remove = Some(plan.entries[0].path.clone());
    assert!(cleanup(&plan, &mut model).is_err());
    assert!(model.removed.is_empty());
    assert_eq!(model.entries.len(), plan.entries.len());
}

#[test]
fn malformed_namespace_alias_order_budget_and_duplicate_plans_refuse() {
    for variant in 0..9 {
        let mut plan = plan();
        match variant {
            0 => plan.entries[0].path = "../management".into(),
            1 => plan.entries.swap(0, 1),
            2 => plan.entries[0].identity = plan.entries[1].identity,
            3 => plan.entries[0].kind = file(APP_LIMIT + 1),
            4 => plan.entries[0].mode = 0o666,
            5 => {
                plan.entries[0].kind = Kind::File {
                    size: 1,
                    sha256: "bad".into(),
                }
            }
            6 => plan.entries.insert(0, plan.entries[0].clone()),
            7 => {
                plan.entries.pop();
            }
            _ => plan.provider_identifier = "../../provider".into(),
        }
        let mut model = Model::new(&plan);
        assert!(cleanup(&plan, &mut model).is_err());
        assert!(model.removed.is_empty());
    }
}

#[test]
fn cleanup_retains_the_approved_provider_identifier_profile() {
    let mut plan = plan();
    plan.provider_identifier = ["a".repeat(60), "b".repeat(60), "c".repeat(60)].join(".");
    assert!(plan.provider_identifier.len() > 128);
    plan.validate().unwrap();
    cleanup(&plan, &mut Model::new(&plan)).unwrap();
    for bad in [
        "one".to_owned(),
        "one..two".to_owned(),
        format!("{}.test", "a".repeat(64)),
        vec!["a".repeat(63); 4].join(".") + ".x",
        "one._two".to_owned(),
    ] {
        plan.provider_identifier = bad;
        assert!(plan.validate().is_err());
    }
}
