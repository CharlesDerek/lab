use super::*;

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
