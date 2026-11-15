//! Rolling-maintenance admission checks. Call with authenticated observations only.
//! Admission is deliberately separate from native package/reboot execution.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RebootMode {
    #[default]
    ManualApproval,
    SingleNodeSchedule,
    ClusterSchedule,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub node: String,
    pub observed_at: i64,
    pub healthy_since: i64,
    pub service_eligible: bool,
    pub witness: bool,
    pub healthy: bool,
    pub maintenance: bool,
    pub quorum: bool,
    pub replication_current: bool,
    pub fencing_ready: bool,
    pub clock_synchronized: bool,
}
/// No public endpoint accepts caller-supplied observations to authorize a reboot.
pub fn admit_cluster_node(target: &str, nodes: &[Observation], now: i64) -> Result<()> {
    ensure!(now >= 0 && nodes.len() <= 256, "Invalid observation set");
    let mut ids = HashSet::new();
    for n in nodes {
        ensure!(
            !n.node.is_empty() && ids.insert(&n.node),
            "Duplicate or missing node identity"
        );
        ensure!(
            n.observed_at >= 0
                && n.observed_at <= now
                && n.healthy_since >= 0
                && n.healthy_since <= now,
            "Invalid node timestamps"
        );
        ensure!(
            (0..=30).contains(&(now - n.observed_at)),
            "Refresh all node observations before maintenance"
        );
        ensure!(
            !n.maintenance,
            "Another node is in maintenance; do not overlap operations"
        );
    }
    let selected = nodes
        .iter()
        .find(|n| n.node == target)
        .ok_or_else(|| anyhow::anyhow!("Target node is not enrolled"))?;
    ensure!(
        selected.service_eligible && !selected.witness && selected.healthy,
        "Target is not an eligible healthy service node"
    );
    ensure!(
        nodes.iter().all(|n| n.quorum && n.clock_synchronized),
        "Cluster quorum or clock health is unknown"
    );
    ensure!(
        selected.replication_current && selected.fencing_ready,
        "Target replication or fencing is not ready"
    );
    let peers = nodes
        .iter()
        .filter(|n| {
            n.node != target
                && n.service_eligible
                && !n.witness
                && n.healthy
                && n.replication_current
                && n.fencing_ready
                && (300..).contains(&(now - n.healthy_since))
        })
        .count();
    ensure!(
        peers >= 3,
        "Cluster schedule requires three other healthy service nodes, stable for five minutes; witnesses do not count"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<Observation> {
        (0..4)
            .map(|i| Observation {
                node: format!("node{i}"),
                observed_at: 1000,
                healthy_since: 600,
                service_eligible: true,
                witness: false,
                healthy: true,
                maintenance: false,
                quorum: true,
                replication_current: true,
                fencing_ready: true,
                clock_synchronized: true,
            })
            .collect()
    }
    #[test]
    fn four_service_nodes_are_required() {
        let mut n = fixture();
        assert!(admit_cluster_node("node0", &n, 1000).is_ok());
        n[3].witness = true;
        assert!(admit_cluster_node("node0", &n, 1000).is_err());
    }
    #[test]
    fn stale_duplicate_unstable_or_busy_nodes_fail_closed() {
        let mut n = fixture();
        n[3].observed_at = 900;
        assert!(admit_cluster_node("node0", &n, 1000).is_err());
        n = fixture();
        n[3].node = "node2".into();
        assert!(admit_cluster_node("node0", &n, 1000).is_err());
        n = fixture();
        n[3].healthy_since = 950;
        assert!(admit_cluster_node("node0", &n, 1000).is_err());
        n = fixture();
        n[1].maintenance = true;
        assert!(admit_cluster_node("node0", &n, 1000).is_err());
    }
}
