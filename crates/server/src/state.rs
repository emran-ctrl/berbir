use sqlx::SqlitePool;

use berbir_engine::Template;

use crate::jobs::JobManager;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub jobs: JobManager,
    pub templates: Vec<Template>,
}
