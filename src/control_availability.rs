//! Review status, never an executable capability or native probe.
use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub fn status(product: &str) -> Result<Value> {
    ensure!(crate::roles::valid_product(product), "Unknown product");
    let controls: &[(&str, &str, &str)] = if product == crate::roles::BACKUP_PRODUCT {
        &[
            (
                "backup_approve",
                "manage",
                "actor_bound_backup_supervisor_required",
            ),
            (
                "backup_revoke",
                "manage",
                "actor_bound_backup_supervisor_required",
            ),
            (
                "backup_rotate_certificate",
                "manage",
                "actor_bound_backup_supervisor_required",
            ),
            (
                "backup_pin",
                "operate",
                "actor_bound_backup_supervisor_required",
            ),
            (
                "backup_delete",
                "manage",
                "actor_bound_backup_supervisor_required",
            ),
            (
                "backup_policy",
                "manage",
                "actor_bound_backup_supervisor_required",
            ),
        ]
    } else {
        &[
            (
                "product_logs",
                "operate",
                "bounded_redacted_log_adapter_not_qualified",
            ),
            (
                "product_health",
                "view",
                "scoped_health_adapter_not_qualified",
            ),
            (
                "boot_set",
                "manage",
                "actor_bound_boot_broker_not_implemented",
            ),
            (
                "core_plan",
                "manage",
                "actor_bound_core_broker_not_implemented",
            ),
            (
                "core_apply",
                "manage",
                "actor_bound_core_broker_not_implemented",
            ),
            (
                "core_rollback",
                "manage",
                "actor_bound_core_broker_not_implemented",
            ),
        ]
    };
    Ok(
        json!({"product":product,"native_actions_enabled":false,"controls":controls.iter().map(|(action,level,reason)|json!({"action":action,"required_grant":level,"available":false,"code":"control_unavailable","reason":reason})).collect::<Vec<_>>()}),
    )
}
