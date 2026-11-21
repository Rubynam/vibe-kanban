//! Local account sign-in: `/api/local-auth/*`.
//!
//! These routes work without any cloud API. When local sign-in is enabled,
//! `middleware::require_local_session` guards every other `/api` route with the
//! session cookie issued here.

use axum::{
    Router,
    extract::{Json, State},
    http::{HeaderMap, StatusCode, header},
    response::{AppendHeaders, IntoResponse, Json as ResponseJson, Response},
    routing::{get, post},
};
use db::models::local_user::LocalUserProfile;
use services::services::local_auth::{
    IssuedSession, LocalAuthCredentials, LocalAuthError, LocalAuthStatusResponse,
};
use utils::response::ApiResponse;

use crate::{
    DeploymentImpl,
    error::ApiError,
    middleware::local_auth::{clear_session_cookie, session_cookie, session_token},
};

pub fn router() -> Router<DeploymentImpl> {
    Router::new()
        .route("/local-auth/status", get(status))
        .route("/local-auth/setup", post(setup))
        .route("/local-auth/login", post(login))
        .route("/local-auth/logout", post(logout))
        .route("/local-auth/me", get(me))
        .route("/local-auth/users", post(create_user))
}

async fn status(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
) -> Result<ResponseJson<ApiResponse<LocalAuthStatusResponse>>, ApiError> {
    let token = session_token(&headers);
    let status = deployment.local_auth().status(token.as_deref()).await?;
    Ok(ResponseJson(ApiResponse::success(status)))
}

/// First-run setup: creates the first account and signs it in. Refused once
/// any account exists.
async fn setup(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
    Json(credentials): Json<LocalAuthCredentials>,
) -> Result<Response, ApiError> {
    let session = deployment.local_auth().setup(&credentials).await?;
    tracing::info!(username = %session.user.username, "created first local account");
    Ok(signed_in_response(&session, &headers))
}

async fn login(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
    Json(credentials): Json<LocalAuthCredentials>,
) -> Result<Response, ApiError> {
    let session = match deployment.local_auth().login(&credentials).await {
        Ok(session) => session,
        Err(LocalAuthError::InvalidCredentials) => {
            tracing::warn!("failed local sign-in attempt");
            return Err(LocalAuthError::InvalidCredentials.into());
        }
        Err(e) => return Err(e.into()),
    };
    Ok(signed_in_response(&session, &headers))
}

async fn logout(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(token) = session_token(&headers) {
        deployment.local_auth().logout(&token).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        AppendHeaders([(header::SET_COOKIE, clear_session_cookie(&headers))]),
    ))
}

async fn me(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
) -> Result<ResponseJson<ApiResponse<LocalUserProfile>>, ApiError> {
    let token = session_token(&headers).ok_or(ApiError::Unauthorized)?;
    let user = deployment
        .local_auth()
        .authenticate(&token)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    Ok(ResponseJson(ApiResponse::success(LocalUserProfile::from(
        &user,
    ))))
}

/// Adds another local account. Only reachable with a valid session, because
/// the gate middleware protects this path.
async fn create_user(
    State(deployment): State<DeploymentImpl>,
    Json(credentials): Json<LocalAuthCredentials>,
) -> Result<ResponseJson<ApiResponse<LocalUserProfile>>, ApiError> {
    let user = deployment.local_auth().create_user(&credentials).await?;
    tracing::info!(username = %user.username, "created local account");
    Ok(ResponseJson(ApiResponse::success(LocalUserProfile::from(
        &user,
    ))))
}

fn signed_in_response(session: &IssuedSession, request_headers: &HeaderMap) -> Response {
    (
        AppendHeaders([(
            header::SET_COOKIE,
            session_cookie(&session.token, request_headers),
        )]),
        ResponseJson(ApiResponse::<LocalUserProfile>::success(
            LocalUserProfile::from(&session.user),
        )),
    )
        .into_response()
}
