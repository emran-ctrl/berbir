mod api;
mod db;
mod jobs;
mod report;
mod state;
mod ws;

use axum::Router;
use tower_http::trace::TraceLayer;

use berbir_engine::Scanner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "berbir_server=info,tower_http=info".into()),
        )
        .init();

    let db_url = std::env::var("BERBIR_DB").unwrap_or_else(|_| "sqlite:berbir.db?mode=rwc".into());
    let dist_dir = std::env::var("BERBIR_DIST").unwrap_or_else(|_| "crates/app/dist".to_string());
    let bind = std::env::var("BERBIR_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    let pool = db::connect(&db_url).await?;
    let templates_dir = std::env::var("BERBIR_TEMPLATES")
        .ok()
        .map(std::path::PathBuf::from);
    let templates = berbir_engine::load_template_registry(templates_dir.as_deref())?;
    tracing::info!("loaded {} templates", templates.len());
    let scanner = Scanner::new(templates.clone(), 20)?;

    let events = jobs::EventBus::default();
    let jobs = jobs::JobManager::start(pool.clone(), scanner, events)?;
    let state = state::AppState {
        db: pool,
        jobs,
        templates,
    };

    let app = router(state, &dist_dir);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("berbir listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: state::AppState, dist_dir: &str) -> Router {
    let router: Router<state::AppState> = Router::new()
        .route(
            "/api/scans",
            axum::routing::post(api::create_scan).get(api::list_scans),
        )
        .route("/api/scans/{id}", axum::routing::get(api::get_scan))
        .route("/api/scans/{id}", axum::routing::delete(api::delete_scan))
        .route(
            "/api/scans/{id}/findings",
            axum::routing::get(api::get_findings),
        )
        .route(
            "/api/scans/{id}/report.md",
            axum::routing::get(api::get_report),
        )
        .route("/api/templates", axum::routing::get(api::list_templates))
        .route("/ws/scans/{id}", axum::routing::get(ws::ws_handler))
        .layer(TraceLayer::new_for_http());

    let router = if std::env::var("BERBIR_DEV_CORS").is_ok() {
        router.layer(tower_http::cors::CorsLayer::permissive())
    } else {
        router
    };

    router
        .fallback_service(tower_http::services::ServeDir::new(dist_dir))
        .with_state(state)
}
