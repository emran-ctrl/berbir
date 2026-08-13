use std::rc::Rc;

use berbir_shared::ScanEvent;
use gloo_utils::window;
use uuid::Uuid;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, WebSocket};

fn ws_base() -> String {
    let loc = window().location();
    let protocol = loc.protocol().unwrap_or_default();
    let host = loc.host().unwrap_or_default();
    let scheme = if protocol == "https:" { "wss" } else { "ws" };
    format!("{scheme}://{host}")
}

/// Opens a WebSocket to `/ws/scans/{id}` and forwards parsed `ScanEvent`s
/// to `on_event`. The connection lives for the rest of the page lifetime.
pub fn open_scan_ws(scan_id: Uuid, on_event: impl Fn(ScanEvent) + 'static) {
    let url = format!("{}/ws/scans/{scan_id}", ws_base());
    let Ok(socket) = WebSocket::new(&url) else {
        return;
    };
    let socket = Rc::new(socket);

    let onmsg = Closure::<dyn Fn(MessageEvent)>::new(move |ev: MessageEvent| {
        if let Ok(text) = ev.data().dyn_into::<js_sys::JsString>()
            && let Some(raw) = text.as_string()
            && let Ok(event) = serde_json::from_str::<ScanEvent>(&raw)
        {
            on_event(event);
        }
    });
    socket.set_onmessage(Some(onmsg.as_ref().unchecked_ref()));
    onmsg.forget();

    // Keep the socket (and its closure) alive for the app lifetime.
    std::mem::forget(socket);
}
