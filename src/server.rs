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

#[derive(Deserialize)]
struct BlocklistBody {
    keys: Vec<String>,
    /// Free text stored as the record source, e.g. "ticket #42".
    note: Option<String>,
}

#[derive(Deserialize)]
struct CreateKeyBody {
    name: String,
    #[serde(default)]
    role: Role,
    expires_in_days: Option<u32>,
}

type Data = web::Data<AppState>;

fn opts(st: &AppState, online: Option<bool>) -> CheckOptions {
    CheckOptions { online: online.unwrap_or(st.checker.online_default()) }
}

// ---------------------------------------------------------------------------
// Handlers

#[get("/health")]
async fn health(st: Data) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "database": st.checker.stats(),
        "blocklist": st.checker.blocklist().len(),
        "legacy_keys_supported": st.checker.legacy_supported(),
        "max_batch_size": st.max_batch,
        "auth_required": st.require_auth,
    }))
}

#[get("/check/{key}")]
async fn check_get(st: Data, _u: User, key: web::Path<String>, q: web::Query<OnlineQuery>) -> HttpResponse {
    HttpResponse::Ok().json(st.checker.check_one(key.into_inner(), opts(&st, q.online)).await)
}

#[post("/check")]
async fn check_post(st: Data, _u: User, body: web::Json<CheckBody>) -> HttpResponse {
    let body = body.into_inner();
    HttpResponse::Ok().json(st.checker.check_one(body.key, opts(&st, body.online)).await)
}

#[post("/check/batch")]
async fn check_batch(st: Data, _u: User, body: web::Json<BatchBody>) -> Result<HttpResponse, ApiError> {
    let body = body.into_inner();
    if body.keys.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "keys must not be empty"));
    }
    if body.keys.len() > st.max_batch {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("batch of {} keys exceeds the limit of {}", body.keys.len(), st.max_batch),
        ));
    }
    let started = Instant::now();
    let results = st.checker.check_many(body.keys, opts(&st, body.online)).await;
    Ok(HttpResponse::Ok().json(json!({
        "count": results.len(),
        "valid": results.iter().filter(|r| r.valid).count(),
        "blocked": results.iter().filter(|r| r.blocked).count(),
        "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
        "results": results,
    })))
}

#[get("/errors")]
async fn error_codes(_u: User) -> HttpResponse {
    HttpResponse::Ok().json(codes::all().collect::<Vec<_>>())
}

#[get("/errors/{code}")]
async fn error_code(_u: User, code: web::Path<String>) -> Result<HttpResponse, ApiError> {
    codes::lookup(&code)
        .map(|c| HttpResponse::Ok().json(c))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, format!("unknown error code {code}")))
}

#[get("/blocklist")]
async fn blocklist_stats(st: Data, _u: User) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "count": st.checker.blocklist().len() }))
}

#[get("/blocklist/{key}")]
async fn blocklist_get(st: Data, _u: User, key: web::Path<String>) -> Result<HttpResponse, ApiError> {
    let key = ProductKey::parse(&key).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let record = st.checker.blocklist().get(&key);
    Ok(HttpResponse::Ok().json(json!({ "key": key.as_string(), "blocked": record.is_some(), "record": record })))
}

/// Parse keys, separating the invalid ones so callers get precise feedback.
fn parse_keys(st: &AppState, keys: &[String]) -> Result<(Vec<ProductKey>, Vec<String>), ApiError> {
    if keys.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "keys must not be empty"));
    }
    if keys.len() > st.max_blocklist_batch {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, format!("at most {} keys per request", st.max_blocklist_batch)));
    }
    let mut ok = Vec::with_capacity(keys.len());
    let mut invalid = Vec::new();
    for k in keys {
        match ProductKey::parse(k) {
            Ok(p) => ok.push(p),
            Err(_) => invalid.push(k.clone()),
        }
    }
    Ok((ok, invalid))
}

#[post("/blocklist")]
async fn blocklist_add(st: Data, _a: Admin, body: web::Json<BlocklistBody>) -> Result<HttpResponse, ApiError> {
    let (keys, invalid) = parse_keys(&st, &body.keys)?;
    let record = BlockRecord {
        source: body.note.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "manual".into()),
        error_code: None,
        added_at: Utc::now(),
    };
    let added = st.checker.blocklist().insert_many(&keys, &record).map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({
        "added": added, "already_present": keys.len() - added, "invalid": invalid,
        "total": st.checker.blocklist().len(),
    })))
}

#[post("/blocklist/remove")]
async fn blocklist_remove(st: Data, _a: Admin, body: web::Json<BlocklistBody>) -> Result<HttpResponse, ApiError> {
    let (keys, invalid) = parse_keys(&st, &body.keys)?;
    let removed = st.checker.blocklist().remove_many(&keys).map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({
        "removed": removed, "not_found": keys.len() - removed, "invalid": invalid,
        "total": st.checker.blocklist().len(),
    })))
}

#[delete("/blocklist/{key}")]
async fn blocklist_delete(st: Data, _a: Admin, key: web::Path<String>) -> Result<HttpResponse, ApiError> {
    let key = ProductKey::parse(&key).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    match st.checker.blocklist().remove(&key).map_err(internal)? {
        true => Ok(HttpResponse::NoContent().finish()),
        false => Err(err(StatusCode::NOT_FOUND, "key is not in the blocklist")),
    }
}

#[get("/apikeys")]
async fn keys_list(st: Data, _a: Admin) -> HttpResponse {
    HttpResponse::Ok().json(st.keys.list())
}

#[post("/apikeys")]
async fn keys_create(st: Data, _a: Admin, body: web::Json<CreateKeyBody>) -> Result<HttpResponse, ApiError> {
    let (key, token) = st
        .keys
        .create(&body.name, body.role, body.expires_in_days)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(HttpResponse::Created().json(json!({ "token": token, "key": key })))
}

#[post("/apikeys/{id}/revoke")]
async fn keys_revoke(st: Data, _a: Admin, id: web::Path<String>) -> Result<HttpResponse, ApiError> {
    match st.keys.revoke(&id).map_err(internal)? {
        true => Ok(HttpResponse::NoContent().finish()),
        false => Err(err(StatusCode::NOT_FOUND, "no such key")),
    }
}

#[derive(Deserialize)]
struct RateLimitBody {
    /// Requests per minute; `null` or 0 restores the server default.
    requests_per_minute: Option<u32>,
}

#[actix_web::put("/apikeys/{id}/ratelimit")]
async fn keys_ratelimit(st: Data, _a: Admin, id: web::Path<String>, body: web::Json<RateLimitBody>) -> Result<HttpResponse, ApiError> {
    match st.keys.set_rate_limit(&id, body.requests_per_minute).map_err(internal)? {
        true => Ok(HttpResponse::NoContent().finish()),
        false => Err(err(StatusCode::NOT_FOUND, "no such key")),
    }
}

#[delete("/apikeys/{id}")]
async fn keys_delete(st: Data, _a: Admin, id: web::Path<String>) -> Result<HttpResponse, ApiError> {
    match st.keys.delete(&id).map_err(internal)? {
        true => Ok(HttpResponse::NoContent().finish()),
        false => Err(err(StatusCode::NOT_FOUND, "no such key")),
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(health)
            // `/check/batch` must precede `/check/{key}`.
            .service(check_batch)
            .service(check_post)
            .service(check_get)
            .service(error_codes)
            .service(error_code)
            .service(blocklist_stats)
            .service(blocklist_remove)
            .service(blocklist_get)
            .service(blocklist_add)
            .service(blocklist_delete)
            .service(keys_list)
            .service(keys_create)

}