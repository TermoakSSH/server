//! API routes.

pub mod ai;
pub mod entities;
pub mod events;
pub mod sessions;
pub mod sftp;
pub mod teams;
pub mod vaults;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, header};
use axum::routing::get;
use axum::{Json, Router};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Full router.
pub fn router(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .server
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // SFTP uploads are streamed and unlimited; everything else, 8 MiB.
    let uploads = sftp::routes().layer(DefaultBodyLimit::disable());
    Router::new()
        .merge(crate::auth::routes())
        .merge(crate::account::routes())
        .merge(crate::push::routes())
        .merge(entities::routes())
        .merge(sessions::routes())
        .merge(ai::routes())
        .merge(events::routes())
        .merge(teams::routes())
        .merge(vaults::routes())
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .merge(uploads)
        .merge(crate::updates::routes())
        .route(
            "/api/openapi.json",
            get(|| async { Json(crate::openapi::document()) }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .merge(crate::web::routes(&state))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
