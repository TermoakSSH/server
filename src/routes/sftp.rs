//! SFTP run by the server (for clients without their own SSH engine, or to
//! work through the server).

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_ssh::{FileEntry, Sftp};
use utoipa::ToSchema;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/hosts/{id}/sftp/home", get(home))
        .route("/api/v1/hosts/{id}/sftp/list", get(list))
        .route("/api/v1/hosts/{id}/sftp/stat", get(stat))
        .route("/api/v1/hosts/{id}/sftp/download", get(download))
        .route("/api/v1/hosts/{id}/sftp/upload", post(upload))
        .route("/api/v1/hosts/{id}/sftp/mkdir", post(mkdir))
        .route("/api/v1/hosts/{id}/sftp/rename", post(rename))
        .route("/api/v1/hosts/{id}/sftp/delete", post(remove))
        .route("/api/v1/hosts/{id}/sftp/chmod", post(chmod))
}

#[derive(Debug, Deserialize)]
struct PathQuery {
    path: String,
}

async fn open(st: &AppState, u: &AuthUser, host: Id) -> ApiResult<Sftp> {
    st.store
        .get::<termoak_core::model::Host>(u.id(), host)
        .await?;
    let conn = st.pool.get(u.id(), host).await?;
    match conn.sftp().await {
        Ok(s) => Ok(s),
        Err(e) => {
            st.pool.invalidate(u.id(), host).await;
            Err(e.into())
        }
    }
}

fn check_path(p: &str) -> ApiResult<()> {
    if p.is_empty() || p.contains('\0') {
        return Err(ApiError::bad_request("invalid path").with_code("invalid_path"));
    }
    Ok(())
}

async fn home(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let sftp = open(&st, &u, id).await?;
    let home = sftp.home().await;
    sftp.close().await;
    Ok(Json(json!({"path": home?})))
}

async fn list(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<Vec<FileEntry>>> {
    check_path(&q.path)?;
    let sftp = open(&st, &u, id).await?;
    let r = sftp.list(&q.path).await;
    sftp.close().await;
    Ok(Json(r?))
}

async fn stat(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<FileEntry>> {
    check_path(&q.path)?;
    let sftp = open(&st, &u, id).await?;
    let r = sftp.stat(&q.path).await;
    sftp.close().await;
    Ok(Json(r?))
}

/// Streaming download (without loading the file into memory).
async fn download(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Response> {
    check_path(&q.path)?;
    let sftp = open(&st, &u, id).await?;
    let entry = sftp.stat(&q.path).await?;
    let name = entry.name.replace('"', "");
    let (writer, reader) = tokio::io::duplex(256 * 1024);
    let path = q.path.clone();
    tokio::spawn(async move {
        if let Err(e) = sftp.download(&path, writer, None).await {
            tracing::warn!(error = %e, %path, "SFTP download interrupted");
        }
        sftp.close().await;
    });
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "sftp.download",
            Some(id.to_string()),
            json!({"path": q.path}),
        )
        .await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, entry.size.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(reader)),
    )
        .into_response())
}

/// Streaming upload: the request body is the file content.
async fn upload(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<PathQuery>,
    body: Body,
) -> ApiResult<Json<Value>> {
    check_path(&q.path)?;
    let sftp = open(&st, &u, id).await?;
    let stream = body
        .into_data_stream()
        .map_err(|e| std::io::Error::other(e.to_string()));
    let reader = tokio_util::io::StreamReader::new(stream);
    let r = sftp.upload(reader, &q.path, None).await;
    sftp.close().await;
    let bytes = r?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "sftp.upload",
            Some(id.to_string()),
            json!({"path": q.path, "bytes": bytes}),
        )
        .await?;
    Ok(Json(json!({"ok": true, "bytes": bytes})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MkdirReq {
    pub path: String,
    #[serde(default)]
    pub parents: bool,
}

async fn mkdir(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<MkdirReq>,
) -> ApiResult<Json<Value>> {
    check_path(&req.path)?;
    let sftp = open(&st, &u, id).await?;
    let r = if req.parents {
        sftp.mkdir_all(&req.path).await
    } else {
        sftp.mkdir(&req.path).await
    };
    sftp.close().await;
    r?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenameReq {
    pub from: String,
    pub to: String,
}

async fn rename(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<RenameReq>,
) -> ApiResult<Json<Value>> {
    check_path(&req.from)?;
    check_path(&req.to)?;
    let sftp = open(&st, &u, id).await?;
    let r = sftp.rename(&req.from, &req.to).await;
    sftp.close().await;
    r?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "sftp.rename",
            Some(id.to_string()),
            json!({"from": req.from, "to": req.to}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteReq {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

async fn remove(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<DeleteReq>,
) -> ApiResult<Json<Value>> {
    check_path(&req.path)?;
    if req.path.trim() == "/" {
        return Err(ApiError::bad_request("cannot delete the root directory")
            .with_code("cannot_delete_root"));
    }
    let sftp = open(&st, &u, id).await?;
    let r = async {
        let entry = sftp.stat(&req.path).await?;
        if entry.kind == termoak_ssh::FileKind::Dir {
            sftp.remove_dir(&req.path, req.recursive).await
        } else {
            sftp.remove_file(&req.path).await
        }
    }
    .await;
    sftp.close().await;
    r?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "sftp.delete",
            Some(id.to_string()),
            json!({"path": req.path, "recursive": req.recursive}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChmodReq {
    pub path: String,
    /// Permissions in octal (`"755"`).
    pub mode: String,
}

async fn chmod(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<ChmodReq>,
) -> ApiResult<Json<Value>> {
    check_path(&req.path)?;
    let mode = u32::from_str_radix(req.mode.trim_start_matches("0o"), 8).map_err(|_| {
        ApiError::bad_request("invalid mode (use octal, e.g. 644)").with_code("invalid_mode")
    })?;
    let sftp = open(&st, &u, id).await?;
    let r = sftp.chmod(&req.path, mode).await;
    sftp.close().await;
    r?;
    Ok(Json(json!({"ok": true})))
}
