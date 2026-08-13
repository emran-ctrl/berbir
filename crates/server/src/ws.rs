//! WebSocket endpoint: streams `ScanEvent`s for a scan to the dashboard.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use berbir_shared::ScanEvent;

use crate::db;
use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(scan_id): Path<Uuid>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, scan_id, state))
}

async fn handle_socket(socket: WebSocket, scan_id: Uuid, state: AppState) {
    let Some(rx) = state.jobs.events.subscribe(scan_id).await else {
        // No event channel for this scan; nothing to stream.
        return;
    };

    let (mut sink, mut stream) = socket.split();
    let mut rx = rx;

    // Send the current persisted status so a late client still gets context.
    if let Ok(Some(scan)) = db::get_scan(&state.db, scan_id).await {
        let event = ScanEvent::StatusChange {
            scan_id,
            status: scan.status,
        };
        if let Ok(text) = serde_json::to_string(&event)
            && sink.send(Message::Text(text.into())).await.is_err() {
                return;
            }
    }

    loop {
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(event) => {
                        let Ok(text) = serde_json::to_string(&event) else { continue };
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(p))) => {
                        if sink.send(Message::Pong(p)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
