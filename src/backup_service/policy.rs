use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    Busy,
    Unsafe,
    Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArrayHealth {
    Healthy,
    Degraded,
    Rebuilding,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: u64,
    pub interval_seconds: u64,
    pub recovery_point_seconds: u64,
    pub keep_snapshots: u32,
    pub reserve_bytes: u64,
    pub max_deferral_seconds: u64,
    pub bandwidth_percent: u8,
    pub monthly_node_bytes: Option<u64>,
    pub monthly_server_bytes: Option<u64>,
    pub required_copies: u32,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (60..=31_536_000).contains(&self.interval_seconds)
                && (60..=31_536_000).contains(&self.recovery_point_seconds),
            "Choose a backup interval and recovery-point goal"
        );
        ensure!(
            (2..=10000).contains(&self.keep_snapshots),
            "Retention must keep at least two snapshots"
        );
        ensure!(
            (1..=100).contains(&self.bandwidth_percent)
                && self.required_copies > 0
                && self.required_copies <= 32,
            "Invalid bandwidth share or copy goal"
        );
        ensure!(
            (60..=604800).contains(&self.max_deferral_seconds),
            "Deferral must be one minute–seven days"
        );
        Ok(())
    }
    pub fn reserve(&self, total: u64) -> u64 {
        self.reserve_bytes.max(total / 20)
    }
}
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Normal,
    Throttled,
    Wait,
    Blocked,
}
pub fn admission(
    state: Readiness,
    observed_at: i64,
    now: i64,
    deferred_for: u64,
    manual_busy_override: bool,
    p: &Policy,
) -> Admission {
    if observed_at < 0 || observed_at > now || now - observed_at > 90 {
        return Admission::Blocked;
    }
    match state {
        Readiness::Unsafe | Readiness::Unknown => Admission::Blocked,
        Readiness::Ready => Admission::Normal,
        Readiness::Busy if manual_busy_override || deferred_for >= p.max_deferral_seconds => {
            Admission::Throttled
        }
        _ => Admission::Wait,
    }
}
#[derive(Serialize, Deserialize, Default)]
pub struct Hysteresis {
    pub busy: bool,
    pub candidate_since: Option<i64>,
    pub last_observation: Option<i64>,
}
impl Hysteresis {
    pub fn observe(&mut self, now: i64, high: bool, low: bool) -> Readiness {
        if self
            .last_observation
            .is_some_and(|t| now <= t || now - t > 90)
        {
            self.candidate_since = None;
        }
        self.last_observation = Some(now);
        let change = if self.busy { low && !high } else { high };
        if change {
            let start = *self.candidate_since.get_or_insert(now);
            if now - start >= 180 {
                self.busy = !self.busy;
                self.candidate_since = None;
            }
        } else {
            self.candidate_since = None;
        }
        if self.busy {
            Readiness::Busy
        } else {
            Readiness::Ready
        }
    }
}
#[derive(Serialize)]
pub struct Estimate {
    pub minimum_bytes: u64,
    pub recommended_bytes: u64,
    pub transfer_seconds: Option<u64>,
    pub restore_seconds: Option<u64>,
    pub rpo_achievable: bool,
    pub assumes_compression_or_sharing: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstimateInput {
    pub full_bytes: u64,
    pub growth_bytes: u64,
    pub logs_bytes: u64,
    pub retained: u32,
    pub backfill_bytes: u64,
    pub reserve: u64,
    pub upload_bps: u64,
    pub restore_bps: u64,
    pub rpo: u64,
}
pub fn estimate(input: &EstimateInput) -> Result<Estimate> {
    let EstimateInput {
        full_bytes,
        growth_bytes,
        logs_bytes,
        retained,
        backfill_bytes,
        reserve,
        upload_bps,
        restore_bps,
        rpo,
    } = *input;
    ensure!(retained >= 2, "Retain at least two snapshots");
    let copies = full_bytes
        .checked_add(growth_bytes)
        .and_then(|v| v.checked_mul(u64::from(retained) + 1))
        .ok_or_else(|| anyhow::anyhow!("Capacity estimate overflow"))?;
    let minimum = copies
        .checked_add(logs_bytes)
        .and_then(|v| v.checked_add(backfill_bytes))
        .and_then(|v| v.checked_add(reserve))
        .ok_or_else(|| anyhow::anyhow!("Capacity estimate overflow"))?;
    let recommended = minimum
        .checked_add(minimum / 4)
        .ok_or_else(|| anyhow::anyhow!("Capacity estimate overflow"))?;
    let duration = |bytes: u64, speed: u64| {
        if speed == 0 {
            None
        } else {
            Some(bytes.div_ceil(speed))
        }
    };
    let transfer = duration(
        full_bytes
            .checked_add(backfill_bytes)
            .ok_or_else(|| anyhow::anyhow!("Size overflow"))?,
        upload_bps,
    );
    Ok(Estimate {
        minimum_bytes: minimum,
        recommended_bytes: recommended,
        transfer_seconds: transfer,
        restore_seconds: duration(full_bytes, restore_bps),
        rpo_achievable: transfer.is_some_and(|t| t <= rpo),
        assumes_compression_or_sharing: false,
    })
}
