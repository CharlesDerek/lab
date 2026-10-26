//! Actual owner transitions with stubbed ES create/delete, not an entitled run.
use super::*;
use std::{cell::RefCell, sync::atomic::Ordering};

#[derive(Default)]
struct Effects {
    created: usize,
    unsubscribed: usize,
    deleted: usize,
    fail_delete: bool,
    fail_unsubscribe: bool,
    null_success: bool,
    nonnull_failure: bool,
    retained: Option<Handler>,
}
thread_local! { static EFFECTS: RefCell<Effects> = RefCell::new(Effects::default()); }
fn api() -> LifetimeApi {
    LifetimeApi {
        create: |out, block| {
            EFFECTS.with(|effects| {
                let mut effects = effects.borrow_mut();
                effects.created += 1;
                assert!(out.is_null());
                effects.retained = Some(block.clone());
                if !effects.null_success {
                    *out = NonNull::<sys::es_client_t>::dangling().as_ptr();
                }
                if effects.nonnull_failure {
                    sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_ERR_INTERNAL
                } else {
                    sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS
                }
            })
        },
        unsubscribe: |client| {
            EFFECTS.with(|effects| {
                assert!(!client.is_null());
                let mut e = effects.borrow_mut();
                e.unsubscribed += 1;
                if e.fail_unsubscribe {
                    sys::es_return_t::ES_RETURN_ERROR
                } else {
                    sys::es_return_t::ES_RETURN_SUCCESS
                }
            })
        },
        delete: |client| {
            EFFECTS.with(|effects| {
                assert!(!client.is_null());
                let mut e = effects.borrow_mut();
                e.deleted += 1;
                if e.fail_delete {
                    sys::es_return_t::ES_RETURN_ERROR
                } else {
                    e.retained.take();
                    sys::es_return_t::ES_RETURN_SUCCESS
                }
            })
        },
    }
}
fn owner(shared: Arc<Shared>) -> crate::Result<Owner> {
    Owner::new_with_api(
        shared.clone(),
        callback(
            shared,
            "a".repeat(64),
            MacosMachTimebase {
                numerator: 1,
                denominator: 1,
            },
        ),
        api(),
    )
}
fn reset(effects: Effects) {
    EFFECTS.with(|e| *e.borrow_mut() = effects);
}

#[test]
fn raw_client_shutdown_is_exactly_once_and_releases_capture_after_confirmed_delete() {
    reset(Effects::default());
    let shared = Arc::new(Shared::default());
    let weak = Arc::downgrade(&shared);
    let mut source = owner(shared.clone()).unwrap();
    drop(shared);
    source.stop().unwrap();
    source.stop().unwrap();
    drop(source);
    assert!(weak.upgrade().is_none());
    EFFECTS.with(|e| {
        let e = e.borrow();
        assert_eq!((e.created, e.unsubscribed, e.deleted), (1, 1, 1));
        assert!(e.retained.is_none());
    });
}

#[test]
fn raw_client_failed_delete_retains_callback_and_can_never_acknowledge_stop() {
    reset(Effects {
        fail_delete: true,
        ..Default::default()
    });
    let shared = Arc::new(Shared::default());
    let mut source = owner(shared.clone()).unwrap();
    assert!(source.stop().is_err());
    assert!(source.stop().is_err());
    drop(source);
    assert!(shared.closing.load(Ordering::SeqCst));
    let block = EFFECTS.with(|e| e.borrow().retained.as_ref().unwrap().clone());
    // Closing rejects before any native Message dereference or retain call.
    block.call((NonNull::dangling(), NonNull::dangling()));
    assert_eq!(shared.counters.received.load(Ordering::SeqCst), 0);
    assert!(shared.counters.failed.load(Ordering::SeqCst));
    EFFECTS.with(|e| assert_eq!(e.borrow().deleted, 1));
    reset(Effects::default());
}

#[test]
fn raw_client_contradictory_creation_refuses_without_using_or_retrying_handle() {
    for effects in [
        Effects {
            null_success: true,
            ..Default::default()
        },
        Effects {
            nonnull_failure: true,
            ..Default::default()
        },
    ] {
        reset(effects);
        let shared = Arc::new(Shared::default());
        assert!(owner(shared.clone()).is_err());
        assert!(shared.closing.load(Ordering::SeqCst));
        EFFECTS.with(|e| {
            let e = e.borrow();
            assert_eq!(e.created, 1);
            assert_eq!(e.deleted, 0);
            assert_eq!(e.unsubscribed, 0);
        });
    }
    reset(Effects::default());
}

#[test]
fn unsubscribe_failure_still_deletes_exactly_once_and_never_reports_clean_stop() {
    reset(Effects {
        fail_unsubscribe: true,
        ..Default::default()
    });
    let mut source = owner(Arc::new(Shared::default())).unwrap();
    assert!(source.stop().is_err());
    assert!(source.stop().is_err());
    drop(source);
    EFFECTS.with(|e| {
        let e = e.borrow();
        assert_eq!((e.created, e.unsubscribed, e.deleted), (1, 1, 1));
        assert!(e.retained.is_none());
    });
}
