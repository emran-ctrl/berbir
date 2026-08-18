use berbir_shared::{CreateScanRequest, Finding, Scan, ScanDetail, TemplateInfo};
use gloo_net::http::Request;
use uuid::Uuid;

pub async fn create_scan(req: CreateScanRequest) -> Result<Scan, String> {
    let resp = Request::post("/api/scans")
        .json(&req)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status() != 201 && resp.status() != 200 {
        return Err(server_error(&resp)
            .await
            .unwrap_or_else(|| format!("scan failed with status {}", resp.status())));
    }
    resp.json::<Scan>().await.map_err(|e| e.to_string())
}

async fn server_error(resp: &gloo_net::http::Response) -> Option<String> {
    let text = resp.text().await.ok()?;
    let body: serde_json::Value = serde_json::from_str(&text).ok()?;
    body.get("error").and_then(|e| e.as_str()).map(String::from)
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

pub async fn delete_scan(id: Uuid) -> Result<(), String> {
    let resp = Request::delete(&format!("/api/scans/{id}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status() != 204 && resp.status() != 200 {
        return Err(format!("delete failed with status {}", resp.status()));
    }
    Ok(())
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
