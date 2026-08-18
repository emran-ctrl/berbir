//! REST + WebSocket API surface.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use berbir_shared::{CreateScanRequest, Finding, Scan, ScanDetail, TemplateInfo};

use crate::db;
use crate::state::AppState;

/// `POST /api/scans` — create and enqueue a scan.
pub async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<CreateScanRequest>,
) -> Response {
    if let Some(ids) = &req.template_ids {
        let known: std::collections::HashSet<&str> =
            state.templates.iter().map(|t| t.id.as_str()).collect();
        let unknown: Vec<&String> = ids
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .collect();
        if !unknown.is_empty() {
            let joined = unknown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown template ids: {joined}") })),
            )
                .into_response();
        }
    }

    match state.jobs.submit(req).await {
        Ok(scan) => (StatusCode::CREATED, Json(scan)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `GET /api/scans` — list scans (parents grouped by creation time).
pub async fn list_scans(State(state): State<AppState>) -> Result<Json<Vec<Scan>>, ApiError> {
    let scans = db::list_scans(&state.db).await?;
    Ok(Json(scans))
}

/// `DELETE /api/scans/{id}` — remove a scan, its descendant scans, and findings.
pub async fn delete_scan(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    match db::delete_scan(&state.db, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => ApiError::not_found().into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// `GET /api/scans/{id}` — a scan plus its aggregated findings.
pub async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanDetail>, ApiError> {
    let Some(scan) = db::get_scan(&state.db, id).await? else {
        return Err(ApiError::not_found());
    };
    let findings = db::get_findings_recursive(&state.db, id).await?;
    Ok(Json(ScanDetail { scan, findings }))
}

/// `GET /api/scans/{id}/findings` — aggregated findings (includes children).
pub async fn get_findings(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Finding>>, ApiError> {
    let findings = db::get_findings_recursive(&state.db, id).await?;
    Ok(Json(findings))
}

/// `GET /api/scans/{id}/report.md` — Markdown report.
pub async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let Some(scan) = db::get_scan(&state.db, id).await? else {
        return Err(ApiError::not_found());
    };
    let findings = db::get_findings_recursive(&state.db, id).await?;
    let body = crate::report::render_markdown(&scan, &findings);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"scan-{id}.md\""))
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("attachment")),
    );
    Ok((headers, body).into_response())
}

/// `GET /api/templates` — available built-in templates.
pub async fn list_templates(
    State(state): State<AppState>,
) -> Result<Json<Vec<TemplateInfo>>, ApiError> {
    let summaries = state
        .templates
        .iter()
        .map(|t| TemplateInfo {
            id: t.id.clone(),
            name: t.info.name.clone(),
            severity: t.info.severity.clone(),
        })
        .collect();
    Ok(Json(summaries))
}

/// Error type serialized as `{ "error": "..." }`.
pub struct ApiError(anyhow::Error);

impl ApiError {
    fn not_found() -> Self {
        ApiError(anyhow::anyhow!("scan not found"))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = if self.0.to_string().contains("not found") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (
            status,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}
