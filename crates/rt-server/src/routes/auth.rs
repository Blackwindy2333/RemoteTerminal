//! Login, logout, session introspection and one-time WebSocket tickets.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::Json;
use rt_core::auth::{self, AuthKind};
use rt_core::logging::AuditEvent;
use rt_core::RtError;
use rt_protocol::error::ErrorCode;
use rt_protocol::ws::WS_PATH;
use rt_protocol::{Ack, LoginRequest, LoginResponse, SessionInfo, WsTicketResponse};

use crate::middleware::{
    client_of, json_body, req_id, session_of, ApiErr, ApiResult, PresentedToken,
};
use crate::state::{AppState, WS_TICKET_TTL_MS};

/// `POST /api/v1/auth/login` — password login with per-IP lockout.
pub(crate) async fn login(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<LoginResponse>> {
    let request_id = req_id(&req);
    let client = client_of(&req);
    let cfg = state.config();
    let body: LoginRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;

    if !auth::ip_allowed(&cfg.server.ip_allowlist, &client.ip) {
        return Err(ApiErr::new(
            ErrorCode::Forbidden,
            "client address is not allowed",
        ));
    }

    // Lockout is checked before touching the password: that keeps the Argon2
    // cost off the table for brute-force traffic.
    if let Err(err) = state.login_limiter().check(&client.ip) {
        let (message, retry_after) = match err {
            RtError::RateLimited {
                message,
                retry_after_secs,
            } => (message, retry_after_secs),
            other => (other.public_message(), 60),
        };
        state.record_audit(
            AuditEvent::new("auth.login", "locked")
                .user(body.username.clone())
                .remote(client.remote())
                .detail(message.clone())
                .request_id(request_id.clone()),
        );
        return Err(ApiErr::new(ErrorCode::Locked, message)
            .with_retry_after(retry_after)
            .with_request_id(request_id));
    }

    // A per-account counter stops one client from burning through a whole
    // user name while rotating source addresses (SECURITY.md S-22).
    if let Err(err) = state.user_throttle().check(&crate::state::username_key(&body.username)) {
        let (message, retry_after) = match err {
            RtError::RateLimited {
                message,
                retry_after_secs,
            } => (message, retry_after_secs),
            other => (other.public_message(), 60),
        };
        state.record_audit(
            AuditEvent::new("auth.login", "throttled")
                .user(body.username.clone())
                .remote(client.remote())
                .detail(message.clone())
                .request_id(request_id.clone()),
        );
        return Err(ApiErr::new(ErrorCode::RateLimited, message)
            .with_retry_after(retry_after)
            .with_request_id(request_id));
    }

    // Credentials come from the live snapshot so edited users apply at once.
    let users = state.credentials().users.clone();
    let username = body.username.clone();
    let password = body.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        auth::verify_user(&users, &username, &password)
            .map(|user| (user.name.clone(), auth::scope_of(user)))
    })
    .await
    .map_err(|err| ApiErr::internal(format!("login worker failed: {err}")))?;

    let (username, scope) = match verified {
        Ok(found) => found,
        Err(err) => {
            let remaining = state.login_limiter().record_failure(&client.ip);
            let account = state.user_throttle().record_failure(&crate::state::username_key(&body.username));
            state.record_audit(
                AuditEvent::new("auth.login", "failure")
                    .user(body.username.clone())
                    .remote(client.remote())
                    .target(body.username.clone())
                    .detail(format!(
                        "{} (ip attempts left={remaining}, account failures={}, account backoff={}s)",
                        err.public_message(),
                        account.failures,
                        account.retry_after_secs
                    ))
                    .request_id(request_id.clone()),
            );
            tracing::info!(
                target: "auth",
                user = %body.username,
                remote = %client.ip,
                remaining_ip_attempts = remaining,
                account_failures = account.failures,
                "login failed"
            );
            // One uniform answer: no attempt counters, no hints about which
            // half of the credential pair was wrong (SECURITY.md S-32).
            return Err(ApiErr::new(
                ErrorCode::Unauthorized,
                "invalid username or password",
            )
            .with_request_id(request_id));
        }
    };

    state.login_limiter().record_success(&client.ip);
    state.user_throttle().record_success(&crate::state::username_key(&body.username));
    let (token, session) = state.session_store().issue(
        &username,
        scope,
        AuthKind::Password,
        body.device_name.clone(),
        Some(client.remote()),
    );
    let expires_in_secs = session.expires_in_secs(auth::now_ms());

    state.record_audit(
        AuditEvent::new("auth.login", "success")
            .user(username.clone())
            .scope(scope.as_str())
            .remote(client.remote())
            .detail(format!("device={}", body.device_name.as_deref().unwrap_or("-")))
            .request_id(request_id.clone()),
    );
    tracing::info!(target: "auth", user = %username, scope = %scope.as_str(), remote = %client.ip, "login ok");

    Ok(Json(LoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in_secs,
        expires_at: auth::rfc3339_ms(session.expires_at_ms),
        scope,
        username,
        server: state.server_info_with_scope(Some(scope)),
    }))
}

/// `POST /api/v1/auth/logout` — revokes the presented session token.
pub(crate) async fn logout(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<Ack>> {
    let ctx = session_of(&req)?;
    let request_id = req_id(&req);
    let token = req.extensions().get::<PresentedToken>().map(|t| t.0.clone());
    let revoked = token
        .as_deref()
        .map(|t| state.revoke_session(t))
        .unwrap_or(false);

    state.record_audit(
        ctx.audit("auth.logout", if revoked { "success" } else { "noop" })
            .request_id(request_id),
    );

    Ok(Json(if revoked {
        Ack::with_message("session ended")
    } else {
        Ack::with_message("no revocable session for this credential")
    }))
}

/// `GET /api/v1/auth/me` — the caller's own session description.
pub(crate) async fn me(State(state): State<Arc<AppState>>, req: Request) -> ApiResult<Json<SessionInfo>> {
    let ctx = session_of(&req)?;
    let token = req
        .extensions()
        .get::<PresentedToken>()
        .map(|t| t.0.clone())
        .unwrap_or_default();

    // Password sessions live in the store and can report exact timestamps;
    // API keys are stateless, so they get a synthesised view.
    let info = match state.session_store().lookup(&token) {
        Some(session) => session.info(),
        None => SessionInfo {
            username: ctx.username.clone(),
            scope: ctx.scope,
            expires_at: String::new(),
            issued_at: auth::rfc3339_ms(auth::now_ms()),
            auth_kind: ctx.auth_kind.clone(),
            device_name: None,
            remote_addr: ctx.remote.clone(),
        },
    };
    Ok(Json(info))
}

/// `POST /api/v1/auth/ws-ticket` — mints a single-use WebSocket ticket.
pub(crate) async fn ws_ticket(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<WsTicketResponse>> {
    let ctx = session_of(&req)?;
    // The ticket is bound to the address that minted it (SECURITY.md S-24).
    let client = client_of(&req);
    let ticket = state.issue_ticket(&ctx, &client.ip);
    Ok(Json(WsTicketResponse {
        ticket,
        expires_in_secs: (WS_TICKET_TTL_MS / 1000) as u64,
        ws_path: WS_PATH.to_string(),
    }))
}

/// JSON body ceiling derived from `server.max_json_kb`.
pub(crate) fn json_limit(max_json_kb: &u64) -> usize {
    (*max_json_kb).max(1).min(64 * 1024) as usize * 1024
}
