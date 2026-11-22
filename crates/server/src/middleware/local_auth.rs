//! Gate that requires a local account session on every `/api` route when local
//! sign-in is enabled (see `services::services::local_auth` for the mode).

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use relay_client::RELAY_HEADER;
use services::services::local_auth::{SESSION_COOKIE_NAME, SESSION_TTL_DAYS};
use utils::response::ApiResponse;

use crate::DeploymentImpl;

/// Header set on 401s from this gate so the frontend can tell "sign in to this
/// server" apart from other 401s (e.g. an expired cloud token).
pub const LOCAL_AUTH_REQUIRED_HEADER: &str = "x-vk-local-auth";

/// Routes reachable without a session: the sign-in flow itself and health.
const PUBLIC_PATHS: &[&str] = &[
    "/health",
    "/local-auth/status",
    "/local-auth/setup",
    "/local-auth/login",
    "/local-auth/logout",
];

/// Relay-auth routes that remote clients call over the relay and that carry
/// their own cryptographic proof (SPAKE2 enrollment code or signing session).
const RELAY_CRYPTO_PATHS: &[&str] = &[
    "/relay-auth/server/spake2/start",
    "/relay-auth/server/spake2/finish",
    "/relay-auth/server/signing-session/refresh",
];

pub async fn require_local_session(
    State(deployment): State<DeploymentImpl>,
    request: Request,
    next: Next,
) -> Response {
    let local_auth = deployment.local_auth();
    if !local_auth.enabled() {
        return next.run(request).await;
    }

    let path = api_relative_path(request.uri().path());
    if PUBLIC_PATHS.contains(&path) || relay_request_has_own_auth(&request, path) {
        return next.run(request).await;
    }

    let Some(token) = session_token(request.headers()) else {
        return local_auth_required();
    };
    match local_auth.authenticate(&token).await {
        Ok(Some(_user)) => next.run(request).await,
        Ok(None) => local_auth_required(),
        Err(e) => {
            tracing::error!(?e, "failed to validate local session");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error("Failed to validate session")),
            )
                .into_response()
        }
    }
}

/// Requests proxied by the relay are authenticated by the relay signature
/// middleware (for every route outside `/relay-auth` and `/host`) or by the
/// SPAKE2/signing-session handshake. The relay header alone proves nothing,
/// so any other relay-flagged path still needs a session.
fn relay_request_has_own_auth(request: &Request, path: &str) -> bool {
    let is_relay = request
        .headers()
        .get(RELAY_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1");
    if !is_relay {
        return false;
    }
    if RELAY_CRYPTO_PATHS.contains(&path) {
        return true;
    }
    !(path.starts_with("/relay-auth/") || path.starts_with("/host/"))
}

/// The gate is layered on the router nested at `/api`, which sees paths with
/// the prefix stripped; strip it here too in case it is ever mounted higher.
fn api_relative_path(path: &str) -> &str {
    match path.strip_prefix("/api") {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ => path,
    }
}

fn local_auth_required() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()>::error(
            "Sign in to this server to continue",
        )),
    )
        .into_response();
    response.headers_mut().insert(
        LOCAL_AUTH_REQUIRED_HEADER,
        HeaderValue::from_static("required"),
    );
    response
}

/// Reads the session token from the `Cookie` header.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE_NAME)
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// `Secure` is added when the browser reached us over HTTPS (directly or via a
/// TLS-terminating proxy), so the cookie still works on plain-http localhost.
fn is_https(headers: &HeaderMap) -> bool {
    let header_is_https = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().to_ascii_lowercase().starts_with("https"))
    };
    header_is_https("x-forwarded-proto") || header_is_https(header::ORIGIN.as_str())
}

pub fn session_cookie(token: &str, request_headers: &HeaderMap) -> String {
    let max_age = SESSION_TTL_DAYS * 24 * 60 * 60;
    let secure = if is_https(request_headers) {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    )
}

pub fn clear_session_cookie(request_headers: &HeaderMap) -> String {
    let secure = if is_https(request_headers) {
        "; Secure"
    } else {
        ""
    };
    format!("{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request as HttpRequest};

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn relay_request(path: &str) -> Request {
        HttpRequest::builder()
            .uri(path)
            .header(RELAY_HEADER, "1")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn reads_session_cookie() {
        let h = headers(&[("cookie", "a=1; vk_local_session=abc123 ; b=2")]);
        assert_eq!(session_token(&h).as_deref(), Some("abc123"));
        let h = headers(&[("cookie", "a=1"), ("cookie", "vk_local_session=zzz")]);
        assert_eq!(session_token(&h).as_deref(), Some("zzz"));
        assert_eq!(
            session_token(&headers(&[("cookie", "vk_local_session=")])),
            None
        );
        assert_eq!(
            session_token(&headers(&[("cookie", "x_vk_local_session=1")])),
            None
        );
        assert_eq!(session_token(&HeaderMap::new()), None);
    }

    #[test]
    fn cookie_attributes() {
        let plain = session_cookie("tok", &HeaderMap::new());
        assert!(plain.starts_with("vk_local_session=tok; "));
        assert!(plain.contains("HttpOnly") && plain.contains("SameSite=Lax"));
        assert!(!plain.contains("Secure"));
        let tls = session_cookie("tok", &headers(&[("x-forwarded-proto", "https")]));
        assert!(tls.ends_with("; Secure"));
        assert!(clear_session_cookie(&HeaderMap::new()).contains("Max-Age=0"));
    }

    #[test]
    fn strips_api_prefix() {
        assert_eq!(api_relative_path("/api/health"), "/health");
        assert_eq!(api_relative_path("/health"), "/health");
        assert_eq!(api_relative_path("/apis/x"), "/apis/x");
    }

    #[test]
    fn relay_header_alone_does_not_bypass_unsigned_routes() {
        // Signed routes: the signature middleware checks these.
        assert!(relay_request_has_own_auth(
            &relay_request("/workspaces"),
            "/workspaces"
        ));
        // SPAKE2 / signing-session handshake.
        let p = "/relay-auth/server/spake2/start";
        assert!(relay_request_has_own_auth(&relay_request(p), p));
        // Not signed and not handshake: still needs a session.
        let p = "/relay-auth/server/clients";
        assert!(!relay_request_has_own_auth(&relay_request(p), p));
        let p = "/host/abc/api/info";
        assert!(!relay_request_has_own_auth(&relay_request(p), p));
        // No relay header at all.
        let req = HttpRequest::builder()
            .uri("/workspaces")
            .body(Body::empty())
            .unwrap();
        assert!(!relay_request_has_own_auth(&req, "/workspaces"));
    }
}
