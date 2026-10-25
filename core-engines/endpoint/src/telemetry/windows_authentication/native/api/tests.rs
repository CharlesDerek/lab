use super::*;
use windows_sys::Win32::Security::Authentication::Identity::{
    Audit_Logon_AccountLockout, Audit_Logon_Logoff, Audit_Logon_Logon,
};

fn synthetic_bookmark() -> Result<Handle> {
    // EvtCreateBookmark parses this synthetic bookmark; no event is queried or
    // changed, and no real account, computer or record contents are involved.
    let synthetic = wide(
        "<BookmarkList><Bookmark Channel='Security' RecordId='1' IsCurrent='true'/></BookmarkList>",
    );
    Handle::checked(
        unsafe { EvtCreateBookmark(synthetic.as_ptr()) },
        "Synthetic bookmark creation",
    )
}

pub(in super::super) fn verify_bookmark_text() -> Result<()> {
    let original = synthetic_bookmark()?;
    let rendered = text(&original, EvtRenderBookmark, 4096)?;
    if rendered.is_empty() || rendered.len() > 4096 || rendered.contains('\0') {
        return Err("Synthetic bookmark text violated its bounds".into());
    }
    let persisted = wide(&rendered);
    let recreated = Handle::checked(
        unsafe { EvtCreateBookmark(persisted.as_ptr()) },
        "Synthetic bookmark recreation",
    )?;
    if text(&recreated, EvtRenderBookmark, 4096)? != rendered {
        return Err("Synthetic bookmark render roundtrip changed".into());
    }
    Ok(())
}

#[test]
fn native_bookmark_roundtrip_preserves_text_bounds_and_refuses_nontext_modes() {
    assert!(
        verify_bookmark_text().is_ok(),
        "Native synthetic bookmark regression failed"
    );
    let original = synthetic_bookmark().expect("Synthetic bookmark creation failed");
    assert!(
        text(&original, EvtRenderBookmark, 1).is_err(),
        "Synthetic bookmark bypassed the text budget"
    );
    for flags in [
        EvtRenderEventValues,
        EvtRenderEventXml | EvtRenderBookmark,
        u32::MAX,
    ] {
        assert!(
            text(&original, flags, 4096).is_err(),
            "Unsupported mode entered the text renderer"
        );
    }
}

fn variant_buffer(payload_bytes: usize) -> Values {
    let used = size_of::<EVT_VARIANT>() + payload_bytes;
    Values {
        buffer: vec![0; used.div_ceil(size_of::<u64>())],
        used,
        count: 1,
    }
}
fn header(values: &mut Values) -> &mut EVT_VARIANT {
    // The owned test buffer has the same alignment and header allocation as
    // Values::render, and contains only synthetic variants and payloads.
    unsafe { &mut *values.buffer.as_mut_ptr().cast::<EVT_VARIANT>() }
}
fn guid_variant(guid: GUID) -> Values {
    let mut values = variant_buffer(size_of::<GUID>());
    let pointer = unsafe {
        values
            .buffer
            .as_mut_ptr()
            .cast::<u8>()
            .add(size_of::<EVT_VARIANT>())
            .cast::<GUID>()
    };
    unsafe { pointer.write_unaligned(guid) };
    *header(&mut values) = EVT_VARIANT {
        Anonymous: EVT_VARIANT_0 { GuidVal: pointer },
        Count: 0,
        Type: EvtVarTypeGuid as u32,
    };
    values
}
fn string_variant(text: &str) -> Values {
    let words = wide(text);
    let mut values = variant_buffer(words.len() * size_of::<u16>());
    let pointer = unsafe {
        values
            .buffer
            .as_mut_ptr()
            .cast::<u8>()
            .add(size_of::<EVT_VARIANT>())
            .cast::<u16>()
    };
    unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), pointer, words.len()) };
    *header(&mut values) = EVT_VARIANT {
        Anonymous: EVT_VARIANT_0 { StringVal: pointer },
        Count: 0,
        Type: EvtVarTypeString as u32,
    };
    values
}
fn scope(values: &Values) -> Result<bool> {
    super::super::Reader::policy_scope(values)
}
fn uncertain(values: &Values) {
    assert!(
        scope(values).is_err(),
        "Invalid synthetic policy scope was accepted"
    );
    assert!(
        scope(values).unwrap_or(true),
        "Unknown synthetic policy scope bypassed conservative loss"
    );
}
pub(in super::super) fn verify_policy_scope_variants() {
    for guid in [Audit_Logon_Logon, Audit_Logon_AccountLockout] {
        assert!(
            scope(&guid_variant(guid)).is_ok_and(|related| related),
            "Related typed audit scope did not retain loss"
        );
        for text in [guid_text(&guid), guid_text(&guid).to_ascii_uppercase()] {
            assert!(
                scope(&string_variant(&text)).is_ok_and(|related| related),
                "Canonical related GUID text did not retain loss"
            );
        }
    }
    for value in [
        guid_variant(Audit_Logon_Logoff),
        string_variant(&guid_text(&Audit_Logon_Logoff)),
    ] {
        assert!(
            scope(&value).is_ok_and(|related| !related),
            "Known unrelated audit scope was not distinguished"
        );
    }
    for kind in [
        EvtVarTypeNull as u32,
        EvtVarTypeUInt64 as u32,
        EvtVarTypeAnsiString as u32,
        EvtVarTypeGuid as u32 | EVT_VARIANT_TYPE_ARRAY,
        EvtVarTypeString as u32 | EVT_VARIANT_TYPE_ARRAY,
    ] {
        let mut value = guid_variant(Audit_Logon_Logon);
        header(&mut value).Type = kind;
        uncertain(&value);
    }
    let mut missing = guid_variant(Audit_Logon_Logon);
    header(&mut missing).Anonymous.GuidVal = std::ptr::null_mut();
    uncertain(&missing);
    let mut truncated = guid_variant(Audit_Logon_Logon);
    truncated.used -= 1;
    uncertain(&truncated);
    let mut outside = guid_variant(Audit_Logon_Logon);
    let pointer = outside
        .buffer
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(outside.used);
    header(&mut outside).Anonymous.GuidVal = pointer.cast();
    uncertain(&outside);
    let mut no_property = guid_variant(Audit_Logon_Logon);
    no_property.count = 0;
    uncertain(&no_property);
    for text in [
        "",
        "unrelated",
        "0cce9215-69ae-11d9-bed3-505054503030",
        "{0cce9215_69ae-11d9-bed3-505054503030}",
        "{0cce9215-69ae-11d9-bed3-50505450303z}",
        " {0cce9215-69ae-11d9-bed3-505054503030}",
        "{0cce9215-69ae-11d9-bed3-505054503030}x",
        "{0cce9215\0-69ae-11d9-bed3-505054503030}",
    ] {
        uncertain(&string_variant(text));
    }
    let mut unterminated = string_variant(&guid_text(&Audit_Logon_Logon));
    unterminated.used -= size_of::<u16>();
    uncertain(&unterminated);
    let mut unaligned = string_variant(&guid_text(&Audit_Logon_Logon));
    let pointer = unsafe { header(&mut unaligned).Anonymous.StringVal };
    header(&mut unaligned).Anonymous.StringVal = pointer.cast::<u8>().wrapping_add(1).cast();
    uncertain(&unaligned);
    let mut invalid_utf16 = string_variant(&guid_text(&Audit_Logon_Logon));
    let pointer = unsafe { header(&mut invalid_utf16).Anonymous.StringVal };
    unsafe { pointer.cast_mut().write(0xd800) };
    uncertain(&invalid_utf16);
}

#[test]
fn policy_scope_accepts_typed_guids_and_preserves_unknown_scope_loss() {
    verify_policy_scope_variants();
}
