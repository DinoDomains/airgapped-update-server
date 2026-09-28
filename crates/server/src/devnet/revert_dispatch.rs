//! Revert command dispatch for M5 → M6.
//!
//! M5 decides that a revert is needed (based on admin action in M7).
//! This module dispatches the `RevertCommand` to the endpoint
//! agent (M6) and records the outcome.

pub use airgap_proto::{RevertCommand, RevertOutcome};

use super::{ApiError, PackageState};
use crate::store::Store;
use crate::audit::AuditLog;

/// Records a revert command in the audit log and prepares it for dispatch.
/// Must be called before the command is sent to the agent.
pub async fn dispatch_revert(
    store: &Store,
    audit: &AuditLog,
    endpoint_id: &str,
    package: &str,
    target_version: &str,
    operator: &str,
) -> Result<RevertCommand, ApiError> {
    if operator.is_empty() {
        return Err(ApiError::EmptyOperator);
    }

    let command_id = format!(
        "revert-{}-{}-{}",
        package,
        target_version,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );

    let cmd = RevertCommand {
        agent_id: endpoint_id.to_string(),
        command_id: command_id.clone(),
        package: package.to_string(),
        target_version: target_version.to_string(),
    };

    // Record the revert request in the audit log before dispatching.
    audit.log(
        operator,
        "revert_command",
        &format!("{endpoint_id}:{package}->{target_version}"),
        &command_id,
    );

    Ok(cmd)
}

/// Process a revert outcome reported by M6.
pub async fn record_revert_outcome(
    store: &Store,
    audit: &AuditLog,
    endpoint_id: &str,
    command_id: &str,
    outcome: RevertOutcome,
    operator: &str,
) {
    audit.log(
        operator,
        "revert_outcome",
        &format!("{endpoint_id}:{command_id}"),
        &format!("{:?}", outcome),
    );
}
