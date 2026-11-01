//! Command execution: one-shot REST invocation and shell discovery.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::Json;
use rt_core::exec::{self, ExecLimits};
use rt_protocol::error::ErrorCode;
use rt_protocol::{ExecRequest, ExecResult, ShellListResponse};

use crate::middleware::{
    json_body, req_id, require_full_scope, session_of, ApiErr, ApiResult,
};
use crate::state::AppState;

use super::auth::json_limit;

/// `GET /api/v1/exec/shells` — which shells this host can run.
///
/// Discovery is harmless, so workspace sessions may call it; running a command
/// is full-scope only.
pub(crate) async fn shells(State(state): State<Arc<AppState>>) -> ApiResult<Json<ShellListResponse>> {
    Ok(Json(state.spawn_blocking_admitted(exec::available_shells).await?))
}

/// `POST /api/v1/exec` — runs one command and answers when it finished.
pub(crate) async fn run(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> ApiResult<Json<ExecResult>> {
    let ctx = session_of(&req)?;
    // A workspace session must not reach arbitrary processes: that would be a
    // full-disk remote code execution bypass of the path jail.
    require_full_scope(&ctx, "executing commands")?;
    let request_id = req_id(&req);
    let cfg = state.config();
    let body: ExecRequest = json_body(req, json_limit(&cfg.server.max_json_kb)).await?;
    body.validate().map_err(ApiErr::bad_request)?;

    let guard = state.guard(ctx.scope)?;
    let limits: ExecLimits = state.exec_limits();
    let permit = state.exec_slots().try_acquire_owned().map_err(|_| {
        ApiErr::new(
            ErrorCode::Unavailable,
            "too many concurrent executions; retry shortly",
        )
        .with_retry_after(1)
    })?;
    let summary = body.clone();
    let shell_label = body.shell.display_name().to_string();

    let result = state
        .spawn_blocking_admitted(move || {
            let _permit = permit;
            exec::run(&guard, &body, &limits)
        })
        .await;

    match &result {
        Ok(out) => {
            state.record_audit(
                ctx.audit("exec.run", "success")
                    .target(shell_label.clone())
                    .detail(format!(
                        "exit={} cmd={}",
                        out.exit_code,
                        truncate_for_audit(&summary.command, 400)
                    ))
                    .request_id(request_id.clone()),
            );
            tracing::info!(
                target: "exec",
                user = %ctx.username,
                shell = %out.shell,
                exit_code = out.exit_code,
                duration_ms = out.duration_ms,
                "exec finished"
            );
        }
        Err(err) => {
            state.record_audit(
                ctx.audit("exec.run", "failure")
                    .target(shell_label)
                    .detail(format!(
                        "{} cmd={}",
                        err.message(),
                        truncate_for_audit(&summary.command, 400)
                    ))
                    .request_id(request_id.clone()),
            );
        }
    }

    Ok(Json(result?))
}

/// Keeps audit lines readable while preserving the interesting head of a command.
fn truncate_for_audit(text: &str, max_chars: usize) -> String {
    let trimmed: String = text.chars().take(max_chars).collect();
    if trimmed.chars().count() < text.chars().count() {
        format!("{trimmed}…")
    } else {
        trimmed
    }
}
