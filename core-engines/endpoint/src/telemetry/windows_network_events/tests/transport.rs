use super::*;
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, Uri},
    routing::post,
    Json, Router,
};
use std::{
    net::TcpListener,
    sync::{Arc, Mutex},
};

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn maximum_originals_use_actual_client_byte_bounded_requests_and_exact_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let values: Vec<_> = (1..=3)
        .map(|sequence| {
            let mut original = event(sequence).original;
            original.extended_data.push(
                athernex_endpoint_protocol::windows_network_events::ExtendedData {
                    reserved1: 0,
                    ext_type: 0,
                    linkage: 0,
                    data_hex: "ab".repeat(48 * 1024 - original.user_data_hex.len() / 2),
                },
            );
            let event = envelope(&WindowsNetworkEvent::from_original(original).unwrap());
            let bytes = serde_json::to_vec(&event).unwrap().len();
            assert!((96 * 1024..128 * 1024).contains(&bytes));
            store.enqueue(&event).unwrap();
            event
        })
        .collect();
    let requests = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let observed = requests.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let app = Router::new().route("/api/endpoint/{endpoint}/{operation}", post(move |uri: Uri, headers: HeaderMap, body: Bytes| {
                let observed = observed.clone();
                async move {
                    if headers.get("authorization").and_then(|header| header.to_str().ok()) != Some(format!("Bearer {}", "b".repeat(64)).as_str()) {
                        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
                    }
                    let response = if uri.path().ends_with("/events") {
                        assert!(body.len() <= 192*1024);
                        let events: Vec<EndpointEvent> = serde_json::from_slice(&body).unwrap();
                        observed.lock().unwrap().push(body.to_vec());
                        serde_json::json!({"durability":"committed","acknowledged":events.len()})
                    } else if uri.path().ends_with("/poll") {
                        serde_json::json!([])
                    } else {
                        serde_json::json!({})
                    };
                    (StatusCode::OK, Json(response))
                }
            }));
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, app).with_graceful_shutdown(async { let _ = stopped.await; }).await.unwrap();
        });
    });
    let server = Server {
        stop: Some(stop),
        worker: Some(worker),
    };
    let config: crate::Config = serde_json::from_value(serde_json::json!({
        "server":format!("http://{address}"), "endpoint_id":"a".repeat(64), "credential":"b".repeat(64),
        "enrollment_token":null, "scanner":directory.path().join("missing-scanner"), "updater":directory.path().join("missing-updater"),
        "scan_roots":[directory.path()], "allow_scripts":false
    })).unwrap();
    crate::Client::new(config).unwrap().cycle(&store).unwrap();
    drop(server);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for (request, expected) in requests.iter().zip(&values) {
        assert_eq!(*request, serde_json::to_vec(&[expected]).unwrap());
    }
    assert_eq!(count(&store), 0);
}
