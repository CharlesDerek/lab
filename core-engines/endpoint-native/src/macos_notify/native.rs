use super::queue::Shared;
use endpoint_sec::sys;
use std::{
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
pub(crate) mod scope;
pub(crate) type Handler =
    block2::RcBlock<dyn Fn(NonNull<sys::es_client_t>, NonNull<sys::es_message_t>)>;

#[derive(Clone, Copy)]
pub(crate) struct LifetimeApi {
    pub(crate) create: fn(&mut *mut sys::es_client_t, &Handler) -> sys::es_new_client_result_t,
    pub(crate) unsubscribe: fn(*mut sys::es_client_t) -> sys::es_return_t,
    pub(crate) delete: fn(*mut sys::es_client_t) -> sys::es_return_t,
}
impl LifetimeApi {
    fn native() -> Self {
        Self {
            create: |out, block| unsafe { sys::es_new_client(out, block) },
            unsubscribe: |client| unsafe { sys::es_unsubscribe_all(client) },
            delete: |client| unsafe { sys::es_delete_client(client) },
        }
    }
}

pub(crate) struct Owner<E: Clone + serde::Serialize + Send + 'static, const LANES: usize> {
    pub(crate) client: Option<NonNull<sys::es_client_t>>,
    block: Option<Handler>,
    shared: Arc<Shared<E, LANES>>,
    api: LifetimeApi,
    failed: bool,
    _thread: PhantomData<Rc<()>>,
}
impl<E: Clone + serde::Serialize + Send + 'static, const LANES: usize> Owner<E, LANES> {
    pub(crate) fn new(
        shared: Arc<Shared<E, LANES>>,
        callback: impl Fn(NonNull<sys::es_message_t>) + std::panic::RefUnwindSafe + 'static,
    ) -> crate::Result<Self> {
        Self::new_with_api(shared, callback, LifetimeApi::native())
    }
    pub(crate) fn new_with_api(
        shared: Arc<Shared<E, LANES>>,
        callback: impl Fn(NonNull<sys::es_message_t>) + std::panic::RefUnwindSafe + 'static,
        api: LifetimeApi,
    ) -> crate::Result<Self> {
        let state = shared.clone();
        let block: Handler = block2::RcBlock::new(
            move |_client: NonNull<sys::es_client_t>, raw: NonNull<sys::es_message_t>| {
                state.callback(|| callback(raw));
            },
        );
        let mut raw = std::ptr::null_mut();
        let code = (api.create)(&mut raw, &block);
        if code != sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS || raw.is_null() {
            // A contradictory pointer/result is uncertain native ownership. Keep
            // callback capture alive until this helper exits; never retry creation.
            if !raw.is_null() || code == sys::es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS {
                shared.closing.store(true, Ordering::SeqCst);
                std::mem::forget(block);
            }
            return Err("Endpoint Security process client creation failed".into());
        }
        Ok(Self {
            client: NonNull::new(raw),
            block: Some(block),
            shared,
            api,
            failed: false,
            _thread: PhantomData,
        })
    }
    pub(crate) fn raw(&self) -> crate::Result<*mut sys::es_client_t> {
        self.client
            .map(NonNull::as_ptr)
            .ok_or_else(|| "Process source client is closed".into())
    }
    pub(crate) fn subscriptions(&self, expected: &[u32]) -> crate::Result<()> {
        let (mut count, mut events) = (0_usize, std::ptr::null_mut());
        let code = unsafe { sys::es_subscriptions(self.raw()?, &mut count, &mut events) };
        struct List(*mut sys::es_event_type_t);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe { libc::free(self.0.cast()) };
            }
        }
        let _list = List(events);
        if code != sys::es_return_t::ES_RETURN_SUCCESS
            || count != expected.len()
            || events.is_null()
        {
            return Err("Process source subscriptions could not be verified".into());
        }
        let mut actual = unsafe { std::slice::from_raw_parts(events, count) }
            .iter()
            .map(|e| e.0)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        if actual != expected {
            return Err("Process source subscriptions changed".into());
        }
        Ok(())
    }
    pub(crate) fn stop(&mut self) -> crate::Result<()> {
        if self.failed {
            return Err("Process source shutdown is unconfirmed".into());
        }
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        let unsubscribe = (self.api.unsubscribe)(client.as_ptr());
        let deleted = (self.api.delete)(client.as_ptr());
        self.shared.closing.store(true, Ordering::SeqCst);
        if deleted != sys::es_return_t::ES_RETURN_SUCCESS {
            self.failed = true;
            self.shared.counters.failed.store(true, Ordering::SeqCst);
            // SDK documents leaked resources on failure. Keep the exact block
            // capture owned until process exit; do not retry or start a new client.
            if let Some(block) = self.block.take() {
                std::mem::forget(block);
            }
            return Err("Endpoint Security process client shutdown failed".into());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.shared.callbacks.load(Ordering::SeqCst) != 0 {
            if Instant::now() >= deadline {
                self.failed = true;
                if let Some(block) = self.block.take() {
                    std::mem::forget(block);
                }
                return Err("Process callback shutdown did not complete".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.block.take();
        if unsubscribe != sys::es_return_t::ES_RETURN_SUCCESS {
            self.failed = true;
            return Err("Process source unsubscribe failed".into());
        }
        Ok(())
    }
}
impl<E: Clone + serde::Serialize + Send + 'static, const LANES: usize> Drop for Owner<E, LANES> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
