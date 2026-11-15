//! Desktop grant management by an authenticated local operator.

use crate::{
    AppState,
    error::{AppError, CanonicalError, RequestId},
};
use aoi_xsg::{AllowFlow, FlowDraft, GrantError, GrantStore, Issuer};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;

// Provision the base64url-encoded SHA-256 digest only. The client keeps the bearer token.
const OPERATOR_DIGEST_ENV: &str = "BROWSEROS_AOI_XSG_OPERATOR_TOKEN_SHA256";
type TokenDigest = [u8; 32];

pub(super) fn router(app: &AppState) -> Router<AppState> {
    if app.config.mode.is_hosted() {
        return Router::new();
    }
    let Some(digest) = std::env::var(OPERATOR_DIGEST_ENV)
        .ok()
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok())
    else {
        return Router::new();
    };
    routes(app.grants.clone(), digest)
}

fn routes<S>(store: Arc<GrantStore>, digest: TokenDigest) -> Router<S> {
    Router::new()
        .route("/api/v1/tasks/{task_id}/grants", post(issue))
        .route("/api/v1/tasks/{task_id}/grants/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .route_layer(middleware::from_fn_with_state(digest, authorize))
        .with_state(store)
}

fn token_digest(token: &str) -> Option<TokenDigest> {
    // The operator provisions a random 32-byte token encoded as unpadded base64url.
    (token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then(|| Sha256::digest(token.as_bytes()).into())
}

async fn authorize(State(expected): State<TokenDigest>, request: Request, next: Next) -> Response {
    let local_peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
    let headers = request.headers();
    if local_peer
        && loopback_host(headers)
        && !super::is_browser_request(headers)
        && presented_digest(headers).is_some_and(|actual| bool::from(actual.ct_eq(&expected)))
    {
        return next.run(request).await;
    }
    CanonicalError::new(
        StatusCode::FORBIDDEN,
        "forbidden",
        "grant management requires an authenticated local operator",
        request.extensions().get::<RequestId>(),
    )
    .into_response()
}

fn loopback_host(headers: &HeaderMap) -> bool {
    header_value(headers, header::HOST)
        .and_then(|host| host.parse::<Authority>().ok())
        .is_some_and(|authority| matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]"))
}

fn presented_digest(headers: &HeaderMap) -> Option<TokenDigest> {
    let (scheme, token) = header_value(headers, header::AUTHORIZATION)?.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(())?;
    token_digest(token)
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let all = headers.get_all(name);
    let mut values = all.iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

async fn issue(
    State(store): State<Arc<GrantStore>>,
    Extension(request_id): Extension<RequestId>,
    Path(task_id): Path<String>,
    Json(draft): Json<FlowDraft>,
) -> Result<(StatusCode, Json<AllowFlow>), CanonicalError> {
    validate_task_id(&request_id, &task_id)?;
    let result =
        tokio::task::spawn_blocking(move || store.issue_grant(Issuer::User, &task_id, draft))
            .await
            .map_err(|error| super::internal(&request_id, error.into()))?;
    let flow = result.map_err(|error| grant_error(&request_id, error))?;
    Ok((StatusCode::CREATED, Json(flow)))
}

#[derive(Serialize)]
struct Revoked {
    revoked: bool,
}

async fn revoke(
    State(store): State<Arc<GrantStore>>,
    Extension(request_id): Extension<RequestId>,
    Path(task_id): Path<String>,
    Json(flow): Json<AllowFlow>,
) -> Result<Json<Revoked>, CanonicalError> {
    validate_task_id(&request_id, &task_id)?;
    let result =
        tokio::task::spawn_blocking(move || store.revoke_grant(Issuer::User, &task_id, &flow))
            .await
            .map_err(|error| super::internal(&request_id, error.into()))?;
    let revoked = result.map_err(|error| grant_error(&request_id, error))?;
    Ok(Json(Revoked { revoked }))
}

fn validate_task_id(request_id: &RequestId, task_id: &str) -> Result<(), CanonicalError> {
    if task_id.trim().is_empty() {
        return Err(super::error(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_task_id",
            "task id is required",
        ));
    }
    Ok(())
}

fn grant_error(request_id: &RequestId, error: GrantError) -> CanonicalError {
    match error {
        GrantError::MissingField(_) => super::error(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            &error.to_string(),
        ),
        GrantError::IssuerRefused(_) => super::error(
            request_id,
            StatusCode::FORBIDDEN,
            "forbidden",
            &error.to_string(),
        ),
        GrantError::Storage(_) => {
            super::internal(request_id, AppError::Internal(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const TOKEN: &str = "test-operator-token-01234567890123456789012";
    const ISSUE: &str = "/api/v1/tasks/example-task/grants";
    const REVOKE: &str = "/api/v1/tasks/example-task/grants/revoke";

    fn draft() -> Value {
        json!({
            "src": { "origin": "https://news.example/story" },
            "dst": "agent",
            "data_class": "page_content",
            "action_class": "read"
        })
    }

    fn test_router(store: Arc<GrantStore>) -> anyhow::Result<Router> {
        let digest = token_digest(TOKEN).ok_or_else(|| anyhow::anyhow!("invalid test token"))?;
        Ok(routes(store, digest).layer(middleware::from_fn(super::super::request_context)))
    }

    async fn request(
        router: &Router,
        path: &str,
        peer: &str,
        host: &str,
        token: Option<&str>,
        extra_header: Option<(&str, &str)>,
        body: Value,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let mut request = axum::http::Request::post(path)
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(peer.parse::<SocketAddr>()?));
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some((name, value)) = extra_header {
            request = request.header(name, value);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        let status = response.status();
        let body = to_bytes(response.into_body(), 8192).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }

    #[tokio::test]
    async fn authenticated_local_operator_can_issue_and_revoke() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("cross-site-grants.json");
        let store = Arc::new(GrantStore::open(file.clone())?);
        let router = test_router(store.clone())?;
        let peer = "127.0.0.1:51232";
        let host = "127.0.0.1:9200";
        let (status, issued) =
            request(&router, ISSUE, peer, host, Some(TOKEN), None, draft()).await?;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(issued["scope"], "this_task");
        assert_eq!(issued["src"]["origin"], "https://news.example");
        assert_eq!(
            GrantStore::open(file.clone())?.load_G("example-task").len(),
            1
        );
        assert!(store.load_G("another-task").is_empty());

        let (status, body) =
            request(&router, REVOKE, peer, host, Some(TOKEN), None, issued).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"revoked": true}));
        assert!(GrantStore::open(file)?.load_G("example-task").is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn grants_refuse_untrusted_requests_and_incomplete_flows() -> anyhow::Result<()> {
        let store = Arc::new(GrantStore::new());
        let router = test_router(store.clone())?;
        let local = "127.0.0.1:51232";
        let host = "127.0.0.1:9200";
        for (peer, host, token, extra) in [
            (local, host, None, None),
            (
                local,
                host,
                Some("test-operator-token-01234567890123456789013"),
                None,
            ),
            (local, "news.example:9200", Some(TOKEN), None),
            ("192.0.2.10:51232", host, Some(TOKEN), None),
            (
                local,
                host,
                Some(TOKEN),
                Some(("origin", "https://news.example")),
            ),
            (
                local,
                host,
                Some(TOKEN),
                Some(("sec-fetch-site", "same-origin")),
            ),
        ] {
            for path in [ISSUE, REVOKE] {
                let (status, _) = request(&router, path, peer, host, token, extra, draft()).await?;
                assert_eq!(status, StatusCode::FORBIDDEN);
            }
        }
        let (status, _) = request(
            &router,
            ISSUE,
            local,
            host,
            Some(TOKEN),
            None,
            json!({"dst": "agent"}),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(store.load_G("example-task").is_empty());
        Ok(())
    }
}
