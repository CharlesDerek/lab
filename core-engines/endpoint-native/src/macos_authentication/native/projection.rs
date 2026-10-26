//! Checked semantic copies from the macOS13 authentication payload prefix.
//! Newer instigator-token fields and wrapper fallback identity are not used.
use athernex_endpoint_protocol::{macos_authentication::*, macos_process_events::*};
use endpoint_sec::{sys, Process};

struct Budget(usize);
impl Budget {
    // The SDK owns each nonnull pointer for the callback. Validate lengths and
    // the complete owned-copy budget before constructing a slice or allocating.
    unsafe fn token(
        &mut self,
        value: &sys::es_string_token_t,
        max: usize,
    ) -> crate::Result<String> {
        if value.length > max || (value.length != 0 && value.data.is_null()) {
            return Err("Invalid authentication token bounds".into());
        }
        self.0 = self
            .0
            .checked_add(
                value
                    .length
                    .checked_mul(2)
                    .ok_or("Authentication copy overflow")?,
            )
            .filter(|n| *n <= athernex_endpoint_protocol::macos_authentication::MAX_ORIGINAL_BYTES)
            .ok_or("Authentication copy budget exceeded")?;
        let bytes = if value.length == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(value.data.cast::<u8>(), value.length) }
        };
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    unsafe fn optional(
        &mut self,
        value: &sys::es_string_token_t,
        max: usize,
    ) -> crate::Result<Option<String>> {
        if value.data.is_null() && value.length == 0 {
            return Ok(None);
        }
        unsafe { self.token(value, max) }.map(Some)
    }
    unsafe fn process(
        &mut self,
        raw: &sys::es_process_t,
        version: u32,
    ) -> crate::Result<MacosProcessProjection> {
        let executable =
            unsafe { raw.executable.as_opt() }.ok_or("Missing authentication executable")?;
        let path_bytes_hex = unsafe {
            self.token(
                &executable.path,
                athernex_endpoint_protocol::macos_authentication::MAX_PATH_BYTES,
            )
        }?;
        let value = Process::new(raw, version);
        Ok(MacosProcessProjection {
            audit_token: value.audit_token().raw_token().val,
            parent_audit_token: value
                .parent_audit_token()
                .ok_or("Missing authentication parent token")?
                .raw_token()
                .val,
            responsible_audit_token: value
                .responsible_audit_token()
                .ok_or("Missing authentication responsible token")?
                .raw_token()
                .val,
            ppid: value.ppid(),
            original_ppid: value.original_ppid(),
            group_id: value.group_id(),
            session_id: value.session_id(),
            executable: MacosExecutable {
                path_bytes_hex,
                path_truncated: executable.path_truncated,
            },
        })
    }
    unsafe fn instigator(
        &mut self,
        raw: *mut sys::es_process_t,
        version: u32,
    ) -> crate::Result<Option<MacosProcessProjection>> {
        match unsafe { raw.as_ref() } {
            Some(process) => unsafe { self.process(process, version) }.map(Some),
            None => Ok(None),
        }
    }
}

// Caller borrows an actual SDK message for its retained callback lifetime (or
// fully initialized synthetic backing in tests). No pointer escapes this call.
pub(super) unsafe fn project(
    raw: &sys::es_message_t,
    stream: &str,
    receipt: u64,
    timebase: &MacosMachTimebase,
) -> crate::Result<MacosAuthentication> {
    if raw.version < athernex_endpoint_protocol::macos_authentication::MIN_MESSAGE_VERSION
        || raw.event_type.0 != EVENT_TYPE
        || raw.action_type.0 != 1
    {
        return Err("Unsupported authentication message profile".into());
    }
    let result = unsafe { raw.action.notify };
    let notify_result = match result.result_type.0 {
        0 => {
            let value = unsafe { result.result.auth }.0;
            if value > 1 {
                return Err("Invalid authentication notify result".into());
            }
            MacosNotifyResult::Auth { result: value }
        }
        1 => MacosNotifyResult::Flags {
            flags: unsafe { result.result.flags },
        },
        _ => return Err("Unknown authentication notify result".into()),
    };
    let event =
        unsafe { raw.event.authentication.as_opt() }.ok_or("Missing authentication payload")?;
    let mut budget = Budget(0);
    let authentication = match event.type_.0 {
        0 => {
            let value =
                unsafe { event.data.od.as_opt() }.ok_or("Missing OD authentication payload")?;
            MacosAuthenticationPayload::OpenDirectory {
                instigator: unsafe { budget.instigator(value.instigator, raw.version) }?,
                record_type_hex: unsafe { budget.token(&value.record_type, MAX_TOKEN_BYTES) }?,
                record_name_hex: unsafe { budget.token(&value.record_name, MAX_TOKEN_BYTES) }?,
                node_name_hex: unsafe { budget.token(&value.node_name, MAX_TOKEN_BYTES) }?,
                db_path_hex: unsafe {
                    budget.optional(
                        &value.db_path,
                        athernex_endpoint_protocol::macos_authentication::MAX_PATH_BYTES,
                    )
                }?,
            }
        }
        1 => {
            let value = unsafe { event.data.touchid.as_opt() }
                .ok_or("Missing TouchID authentication payload")?;
            if value.touchid_mode.0 > 1 {
                return Err("Unsupported TouchID mode".into());
            }
            MacosAuthenticationPayload::TouchId {
                instigator: unsafe { budget.instigator(value.instigator, raw.version) }?,
                mode: value.touchid_mode.0,
                has_uid: value.has_uid,
                // has_uid is the union discriminator. Success and mode are
                // independent facts; the wrapper's stronger predicate loses UID.
                uid: if value.has_uid {
                    Some(unsafe { value.anon0.uid })
                } else {
                    None
                },
            }
        }
        2 => {
            let value = unsafe { event.data.token.as_opt() }
                .ok_or("Missing token authentication payload")?;
            MacosAuthenticationPayload::Token {
                instigator: unsafe { budget.instigator(value.instigator, raw.version) }?,
                pubkey_hash_hex: unsafe { budget.token(&value.pubkey_hash, MAX_TOKEN_BYTES) }?,
                token_id_hex: unsafe { budget.token(&value.token_id, MAX_TOKEN_BYTES) }?,
                kerberos_principal_hex: unsafe {
                    budget.optional(&value.kerberos_principal, MAX_TOKEN_BYTES)
                }?,
            }
        }
        3 => {
            let value = unsafe { event.data.auto_unlock.as_opt() }
                .ok_or("Missing Auto Unlock authentication payload")?;
            if ![1, 2].contains(&value.type_.0) {
                return Err("Unsupported Auto Unlock purpose".into());
            }
            MacosAuthenticationPayload::AutoUnlock {
                username_hex: unsafe { budget.token(&value.username, MAX_TOKEN_BYTES) }?,
                purpose: value.type_.0,
            }
        }
        _ => return Err("Unsupported authentication type".into()),
    };
    let process = unsafe { raw.process.as_opt() }.ok_or("Missing authentication event process")?;
    MacosAuthentication::from_original(MacosAuthenticationOriginal {
        projection_version: athernex_endpoint_protocol::macos_authentication::PROJECTION_VERSION,
        stream_id: stream.into(),
        receipt_sequence: receipt,
        message_version: raw.version,
        event_type: raw.event_type.0,
        action_type: raw.action_type.0,
        notify_result,
        time: MacosEventTime {
            seconds: raw.time.tv_sec,
            nanoseconds: raw.time.tv_nsec,
        },
        mach_time: raw.mach_time,
        mach_timebase: timebase.clone(),
        seq_num: raw.seq_num,
        global_seq_num: raw.global_seq_num,
        event_process: unsafe { budget.process(process, raw.version) }?,
        success: event.success,
        authentication_type: event.type_.0,
        authentication,
    })
    .map_err(|_| "Invalid authentication notification projection".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(bytes: &[u8]) -> sys::es_string_token_t {
        sys::es_string_token_t {
            length: bytes.len(),
            data: bytes.as_ptr().cast(),
        }
    }
    fn null() -> sys::es_string_token_t {
        sys::es_string_token_t {
            length: 0,
            data: std::ptr::null(),
        }
    }
    fn message(
        auth: &mut sys::es_event_authentication_t,
    ) -> (
        Box<sys::es_file_t>,
        Box<sys::es_process_t>,
        Box<sys::es_message_t>,
    ) {
        // These C binding structs contain only zero-valid scalars and pointers.
        // Every pointer read by project is replaced with owned test backing.
        let mut file: Box<sys::es_file_t> = Box::new(unsafe { std::mem::zeroed() });
        file.path = token(b"/synthetic/emitter");
        let mut process: Box<sys::es_process_t> = Box::new(unsafe { std::mem::zeroed() });
        process.executable = sys::ShouldNotBeNull::new(&mut *file);
        process.audit_token.val[5] = 41;
        let mut raw: Box<sys::es_message_t> = Box::new(unsafe { std::mem::zeroed() });
        raw.version = 5;
        raw.time.tv_sec = 1;
        raw.event_type = sys::es_event_type_t(111);
        raw.action_type = sys::es_action_type_t(1);
        raw.process = sys::ShouldNotBeNull::new(&mut *process);
        raw.event.authentication = sys::ShouldNotBeNull::new(auth);
        (file, process, raw)
    }
    fn project_test(raw: &sys::es_message_t) -> crate::Result<MacosAuthentication> {
        unsafe {
            project(
                raw,
                &"a".repeat(64),
                1,
                &MacosMachTimebase {
                    numerator: 1,
                    denominator: 1,
                },
            )
        }
    }

    #[test]
    fn touchid_uid_presence_preserves_every_known_success_and_mode_combination() {
        for success in [false, true] {
            for mode in [0, 1] {
                for has_uid in [false, true] {
                    let mut value = sys::es_event_authentication_touchid_t {
                        instigator: std::ptr::null_mut(),
                        touchid_mode: sys::es_touchid_mode_t(mode),
                        has_uid,
                        anon0: sys::es_event_authentication_touchid_t_anon0 { uid: 501 },
                    };
                    let mut auth = sys::es_event_authentication_t {
                        success,
                        type_: sys::es_authentication_type_t(1),
                        data: sys::es_event_authentication_t_anon0 {
                            touchid: sys::ShouldNotBeNull::new(&mut value),
                        },
                    };
                    let (_file, _process, raw) = message(&mut auth);
                    let result = project_test(&raw).unwrap();
                    assert_eq!(result.reported_success, success);
                    let MacosAuthenticationPayload::TouchId {
                        mode: actual,
                        has_uid: present,
                        uid,
                        instigator,
                    } = result.original.authentication
                    else {
                        panic!("Unexpected synthetic payload")
                    };
                    assert_eq!(
                        (actual, present, uid),
                        (mode, has_uid, has_uid.then_some(501))
                    );
                    assert!(instigator.is_none());
                }
            }
        }
    }

    #[test]
    fn exact_tokens_optional_presence_and_independent_instigator_survive_source_destruction() {
        let mut bytes = vec![0, 255, b'x'];
        let mut value = sys::es_event_authentication_od_t {
            instigator: std::ptr::null_mut(),
            record_type: token(b"Groups"),
            record_name: token(&bytes),
            node_name: token(b"node"),
            db_path: null(),
        };
        let mut auth = sys::es_event_authentication_t {
            success: false,
            type_: sys::es_authentication_type_t(0),
            data: sys::es_event_authentication_t_anon0 {
                od: sys::ShouldNotBeNull::new(&mut value),
            },
        };
        let (_file, _process, raw) = message(&mut auth);
        let retained = project_test(&raw).unwrap();
        bytes.fill(7);
        drop(bytes);
        let MacosAuthenticationPayload::OpenDirectory {
            record_name_hex,
            db_path_hex,
            instigator,
            ..
        } = retained.original.authentication
        else {
            panic!("Unexpected synthetic payload")
        };
        assert_eq!(record_name_hex, "00ff78");
        assert!(db_path_hex.is_none());
        assert!(instigator.is_none());
        value.record_name = token(b"name");
        value.db_path = token(b"");
        let (_other_file, mut other_process, _other_raw) = message(&mut auth);
        other_process.audit_token.val[5] = 72;
        value.instigator = &mut *other_process;
        let result = project_test(&raw).unwrap();
        let MacosAuthenticationPayload::OpenDirectory {
            db_path_hex,
            instigator,
            ..
        } = result.original.authentication
        else {
            panic!("Unexpected synthetic payload")
        };
        assert_eq!(db_path_hex, Some(String::new()));
        assert_eq!(instigator.unwrap().audit_token[5], 72);
        assert_eq!(result.original.event_process.audit_token[5], 41);
    }

    #[test]
    fn all_payload_variants_and_invalid_discriminants_refuse_before_pointer_access() {
        let mut value = sys::es_event_authentication_token_t {
            instigator: std::ptr::null_mut(),
            pubkey_hash: token(b"opaque"),
            token_id: token(b"id"),
            kerberos_principal: null(),
        };
        let mut auth = sys::es_event_authentication_t {
            success: true,
            type_: sys::es_authentication_type_t(2),
            data: sys::es_event_authentication_t_anon0 {
                token: sys::ShouldNotBeNull::new(&mut value),
            },
        };
        let (_file, _process, mut raw) = message(&mut auth);
        assert!(matches!(
            project_test(&raw).unwrap().original.authentication,
            MacosAuthenticationPayload::Token {
                kerberos_principal_hex: None,
                ..
            }
        ));
        value.kerberos_principal = token(b"");
        assert!(
            matches!(project_test(&raw).unwrap().original.authentication,MacosAuthenticationPayload::Token{kerberos_principal_hex:Some(ref v),..} if v.is_empty())
        );
        let mut unlock = sys::es_event_authentication_auto_unlock_t {
            username: token(b"name"),
            type_: sys::es_auto_unlock_type_t(2),
        };
        auth.type_ = sys::es_authentication_type_t(3);
        auth.data.auto_unlock = sys::ShouldNotBeNull::new(&mut unlock);
        assert!(matches!(
            project_test(&raw).unwrap().original.authentication,
            MacosAuthenticationPayload::AutoUnlock { purpose: 2, .. }
        ));
        unlock.type_ = sys::es_auto_unlock_type_t(0);
        assert!(project_test(&raw).is_err());
        for kind in [4, u32::MAX] {
            auth.type_ = sys::es_authentication_type_t(kind);
            auth.data.od = sys::ShouldNotBeNull::new(std::ptr::dangling_mut());
            assert!(project_test(&raw).is_err());
        }
        for kind in 0..4 {
            auth.type_ = sys::es_authentication_type_t(kind);
            auth.data.od = sys::ShouldNotBeNull::new(std::ptr::null_mut());
            assert!(project_test(&raw).is_err());
        }
        raw.event.authentication = sys::ShouldNotBeNull::new(std::ptr::dangling_mut());
        raw.version = 4;
        assert!(project_test(&raw).is_err());
        raw.version = 5;
        raw.event_type = sys::es_event_type_t(9);
        assert!(project_test(&raw).is_err());
        raw.event_type = sys::es_event_type_t(111);
        raw.action_type = sys::es_action_type_t(0);
        assert!(project_test(&raw).is_err());
    }

    #[test]
    fn token_lengths_nulls_and_aggregate_bounds_are_checked_before_slices() {
        let mut budget = Budget(0);
        assert_eq!(
            unsafe { budget.token(&null(), MAX_TOKEN_BYTES) }.unwrap(),
            ""
        );
        let bad = sys::es_string_token_t {
            length: 1,
            data: std::ptr::null(),
        };
        assert!(unsafe { budget.token(&bad, MAX_TOKEN_BYTES) }.is_err());
        let too_long = sys::es_string_token_t {
            length: MAX_TOKEN_BYTES + 1,
            data: std::ptr::dangling(),
        };
        assert!(unsafe { budget.token(&too_long, MAX_TOKEN_BYTES) }.is_err());
        let exact = vec![255; MAX_TOKEN_BYTES];
        assert_eq!(
            unsafe { budget.token(&token(&exact), MAX_TOKEN_BYTES) }
                .unwrap()
                .len(),
            MAX_TOKEN_BYTES * 2
        );
        budget.0 = athernex_endpoint_protocol::macos_authentication::MAX_ORIGINAL_BYTES;
        let out_of_budget = sys::es_string_token_t {
            length: 1,
            data: std::ptr::dangling(),
        };
        assert!(unsafe { budget.token(&out_of_budget, MAX_TOKEN_BYTES) }.is_err());
    }
}
