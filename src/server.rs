//! REST API (actix-web).
//!
//! | Method | Path                          | Role  |
//! |--------|-------------------------------|-------|
//! | GET    | /api/v1/health                | none  |
//! | GET    | /api/v1/check/{key}           | user  |
//! | POST   | /api/v1/check                 | user  |
//! | POST   | /api/v1/check/batch           | user  |
//! | GET    | /api/v1/errors                | user  |
//! | GET    | /api/v1/errors/{code}         | user  |
//! | GET    | /api/v1/blocklist             | user  |
//! | GET    | /api/v1/blocklist/{key}       | user  |
//! | POST   | /api/v1/blocklist             | admin |
//! | POST   | /api/v1/blocklist/remove      | admin |
//! | DELETE | /api/v1/blocklist/{key}       | admin |
//! | GET    | /api/v1/apikeys               | admin |
//! | POST   | /api/v1/apikeys               | admin |
//! | POST   | /api/v1/apikeys/{id}/revoke   | admin |
//! | DELETE | /api/v1/apikeys/{id}          | admin |
//! | PUT    | /api/v1/apikeys/{id}/ratelimit| admin |

use std::future::{ready, Ready};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_web::dev::{Payload, ServerHandle as ActixHandle};
use actix_web::http::StatusCode;
use actix_web::{delete, get, post, web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, ResponseError};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::apikeys::{ApiKey, ApiKeyStore, Role};
use crate::config::Config;
use crate::core::blocklist::BlockRecord;
use crate::core::checker::{CheckOptions, Checker};
use crate::core::codes;
use crate::core::key::ProductKey;

#[derive(Clone)]
pub struct AppState {
    pub checker: Arc<Checker>,
    pub keys: Arc<ApiKeyStore>,
    pub require_auth: bool,
    pub max_batch: usize,
    pub max_blocklist_batch: usize,
    pub rate_limit: crate::config::RateLimitConfig,
    pub limiter: Arc<crate::ratelimit::RateLimiter>,
}

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.0
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.0).json(json!({ "error": self.1 }))
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(status, msg.into())
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ---------------------------------------------------------------------------
// Authentication extractors

fn token(req: &HttpRequest) -> Option<&str> {
    let h = req.headers();
    if let Some(v) = h.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.trim());
    }
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::trim)
}

fn authenticate(req: &HttpRequest) -> Result<Option<ApiKey>, ApiError> {
    let st = req.app_data::<web::Data<AppState>>().ok_or_else(|| internal("state missing"))?;
    match token(req) {
        Some(t) => st
            .keys
            .authenticate(t)
            .map(Some)
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid, revoked or expired API key")),
        None if st.require_auth => Err(err(StatusCode::UNAUTHORIZED, "missing API key")),
        None => Ok(None),
    }
}

/// Any authenticated caller (or anyone when auth is disabled).
pub struct User(#[allow(dead_code)] Option<ApiKey>);

impl FromRequest for User {
    type Error = ApiError;
    type Future = Ready<Result<Self, ApiError>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(authenticate(req).map(User))
    }
}

/// Caller holding an admin key (or anyone when auth is disabled).
pub struct Admin(#[allow(dead_code)] Option<ApiKey>);

impl FromRequest for Admin {
    type Error = ApiError;
    type Future = Ready<Result<Self, ApiError>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(authenticate(req).and_then(|k| match k {
            Some(k) if k.role == Role::Admin => Ok(Admin(Some(k))),
            None => Ok(Admin(None)),
            Some(_) => Err(err(StatusCode::FORBIDDEN, "admin API key required")),
        }))
    }
}

// ---------------------------------------------------------------------------
// Rate limiting

async fn rate_limit(
    req: actix_web::dev::ServiceRequest,
    next: actix_web::middleware::Next<impl actix_web::body::MessageBody + 'static>,
) -> Result<actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>, actix_web::Error> {
    use actix_web::http::header::{HeaderName, HeaderValue};

    let Some(st) = req.app_data::<Data>().cloned() else {
        return next.call(req).await.map(|r| r.map_into_left_body());
    };
    let cfg = &st.rate_limit;
    if !cfg.enabled || req.path().ends_with("/health") {
        return next.call(req).await.map(|r| r.map_into_left_body());
    }
    // Identify the client: API key (with optional per-key quota) or IP address.
    let api_key = token(req.request()).and_then(|t| st.keys.find(t));
    let (client, per_minute) = match &api_key {
        Some(k) => (format!("key:{}", k.id), k.rate_limit_per_minute.unwrap_or(cfg.requests_per_minute)),
        None => {
            let info = req.connection_info();
            let ip = if cfg.trust_proxy_headers { info.realip_remote_addr() } else { info.peer_addr() };
            (format!("ip:{}", ip.unwrap_or("unknown")), cfg.requests_per_minute)
        }
    };
    let quota = crate::ratelimit::Quota { per_minute, burst: cfg.burst.max(1) };
    let d = st.limiter.check(&client, quota);
    let headers = [
        ("ratelimit-limit", d.limit.to_string()),
        ("ratelimit-remaining", d.remaining.to_string()),
        ("ratelimit-reset", d.reset_secs.to_string()),
        ("ratelimit-policy", format!("{};w=60;burst={}", per_minute, quota.burst)),
    ];
    let mut res = if d.allowed {
        next.call(req).await?.map_into_left_body()
    } else {
        let body = HttpResponse::TooManyRequests()
            .insert_header(("retry-after", d.retry_after_secs.to_string()))
            .json(json!({ "error": "rate limit exceeded", "retry_after_secs": d.retry_after_secs }));
        req.into_response(body).map_into_right_body()
    };
    for (name, value) in headers {
        if let Ok(v) = HeaderValue::from_str(&value) {
            res.headers_mut().insert(HeaderName::from_static(name), v);
        }
    }
    Ok(res)
}

// ---------------------------------------------------------------------------
// Request bodies

#[derive(Deserialize)]
struct OnlineQuery {
    online: Option<bool>,
}

#[derive(Deserialize)]
struct CheckBody {
    key: String,
    online: Option<bool>,
}

#[derive(Deserialize)]
struct BatchBody {
    keys: Vec<String>,
    online: Option<bool>,
}

}