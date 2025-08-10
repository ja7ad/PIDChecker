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