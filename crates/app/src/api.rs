use berbir_shared::{CreateScanRequest, Finding, Scan, ScanDetail, TemplateInfo};
use gloo_net::http::Request;
use uuid::Uuid;

pub async fn create_scan(req: CreateScanRequest) -> Result<Scan, String> {
    Request::post("/api/scans")
        .json(&req)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Scan>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn list_scans() -> Result<Vec<Scan>, String> {
    Request::get("/api/scans")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Vec<Scan>>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn get_scan(id: Uuid) -> Result<ScanDetail, String> {
    Request::get(&format!("/api/scans/{id}"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<ScanDetail>()
        .await
        .map_err(|e| e.to_string())
}

pub async fn list_templates() -> Result<Vec<TemplateInfo>, String> {
    Request::get("/api/templates")
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Vec<TemplateInfo>>()
        .await
        .map_err(|e| e.to_string())
}

#[allow(dead_code)]
pub async fn get_findings(id: Uuid) -> Result<Vec<Finding>, String> {
    Request::get(&format!("/api/scans/{id}/findings"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Vec<Finding>>()
        .await
        .map_err(|e| e.to_string())
}
