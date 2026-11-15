//! Bounded host telemetry. Counter resets and missed observations remain gaps.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub at: i64,
    pub boot_id: String,
    pub values: BTreeMap<String, f64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub days: u32,
    pub budget_bytes: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            days: 30,
            budget_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=3650).contains(&self.days),
            "Retention must be 1–3650 days"
        );
        ensure!(
            (16 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.budget_bytes),
            "History budget must be 16 MiB–64 GiB"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Point {
    pub at: i64,
    pub average: f64,
    pub min: f64,
    pub max: f64,
    pub samples: i64,
    pub resolution: i64,
}
#[derive(Default)]
pub struct Collector {
    previous: Option<(i64, String, BTreeMap<String, u64>)>,
}
fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}
fn counter(map: &mut BTreeMap<String, u64>, key: String, text: Option<&str>) {
    if let Some(v) = text.and_then(|s| s.parse().ok()) {
        map.insert(key, v);
    }
}
impl Collector {
    pub fn sample(&mut self, proc: &Path, at: i64) -> Sample {
        let boot_id = read(&proc.join("sys/kernel/random/boot_id"))
            .trim()
            .to_owned();
        let mut values = BTreeMap::new();
        let mut counts = BTreeMap::new();
        let stat = read(&proc.join("stat"));
        if let Some(line) = stat.lines().find(|s| s.starts_with("cpu ")) {
            let parts: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .take(8)
                .filter_map(|x| x.parse().ok())
                .collect();
            if parts.len() >= 4 {
                counts.insert("cpu.total".into(), parts.iter().sum());
                counts.insert(
                    "cpu.idle".into(),
                    parts[3] + parts.get(4).copied().unwrap_or(0),
                );
            }
        }
        let mem = read(&proc.join("meminfo"));
        let memory: BTreeMap<_, _> = mem
            .lines()
            .filter_map(|line| {
                let mut p = line.split_whitespace();
                Some((
                    p.next()?.trim_end_matches(':'),
                    p.next()?.parse::<u64>().ok()? * 1024,
                ))
            })
            .collect();
        for (source, name) in [
            ("MemTotal", "memory.total"),
            ("MemAvailable", "memory.available"),
            ("SwapTotal", "swap.total"),
            ("SwapFree", "swap.free"),
        ] {
            if let Some(v) = memory.get(source) {
                values.insert(name.into(), *v as f64);
            }
        }
        if let (Some(total), Some(available)) = (memory.get("MemTotal"), memory.get("MemAvailable"))
            && *total > 0
        {
            values.insert(
                "memory.used_percent".into(),
                100.0 * (total.saturating_sub(*available)) as f64 / *total as f64,
            );
        }
        for (i, v) in read(&proc.join("loadavg"))
            .split_whitespace()
            .take(3)
            .enumerate()
        {
            if let Ok(v) = v.parse::<f64>() {
                values.insert(format!("load.{}", [1, 5, 15][i]), v);
            }
        }
        if let Some(v) = read(&proc.join("uptime"))
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
        {
            values.insert("uptime.seconds".into(), v);
        }
        for line in read(&proc.join("net/dev")).lines() {
            let Some((name, row)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name == "lo" || name.len() > 32 {
                continue;
            }
            let p: Vec<_> = row.split_whitespace().collect();
            for (index, kind) in [
                (0, "rx_bytes"),
                (8, "tx_bytes"),
                (2, "rx_errors"),
                (10, "tx_errors"),
            ] {
                counter(
                    &mut counts,
                    format!("network.{name}.{kind}"),
                    p.get(index).copied(),
                );
            }
        }
        for line in read(&proc.join("diskstats")).lines() {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() < 14 {
                continue;
            }
            let name = p[2];
            if name.starts_with("loop") || name.starts_with("ram") || name.len() > 32 {
                continue;
            }
            for (i, k) in [(5, "read_sectors"), (9, "write_sectors"), (12, "io_ms")] {
                counter(&mut counts, format!("disk.{name}.{k}"), p.get(i).copied());
            }
        }
        if let Some((then, boot, old)) = &self.previous {
            let dt = at - *then;
            if boot == &boot_id && (1..=30).contains(&dt) {
                if let (Some(t), Some(i), Some(ot), Some(oi)) = (
                    counts.get("cpu.total"),
                    counts.get("cpu.idle"),
                    old.get("cpu.total"),
                    old.get("cpu.idle"),
                ) && t > ot
                    && i >= oi
                    && i - oi <= t - ot
                {
                    values.insert(
                        "cpu.percent".into(),
                        100.0 * (t - ot - (i - oi)) as f64 / (t - ot) as f64,
                    );
                }
                for (name, value) in &counts {
                    if name.starts_with("cpu.") {
                        continue;
                    }
                    if let Some(prior) = old.get(name).filter(|v| value >= *v) {
                        values.insert(
                            format!("{name}_per_second"),
                            (value - prior) as f64 / dt as f64,
                        );
                    }
                }
            }
        }
        self.previous = Some((at, boot_id.clone(), counts));
        values.retain(|_, v| v.is_finite());
        Sample {
            at,
            boot_id,
            values,
        }
    }
}

pub struct History {
    db: Connection,
}
impl History {
    pub fn open(root: &Path) -> Result<Self> {
        let path = root.join("metrics.sqlite");
        let parent = fs::symlink_metadata(root)?;
        ensure!(
            parent.is_dir()
                && !parent.file_type().is_symlink()
                && parent.uid() == unsafe { libc::geteuid() }
                && parent.mode() & 0o077 == 0,
            "Metrics root must be private and owned"
        );
        if let Ok(m) = fs::symlink_metadata(&path) {
            ensure!(
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.nlink() == 1
                    && m.uid() == parent.uid(),
                "Unsafe metrics database"
            );
        }
        let db = Connection::open(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=16777216;
CREATE TABLE IF NOT EXISTS samples(tier INTEGER NOT NULL,at INTEGER NOT NULL,name TEXT NOT NULL,total REAL NOT NULL,low REAL NOT NULL,high REAL NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(tier,at,name));
CREATE INDEX IF NOT EXISTS metric_lookup ON samples(name,at);
CREATE TABLE IF NOT EXISTS latest(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS health(id INTEGER PRIMARY KEY CHECK(id=1),trimmed INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO health VALUES(1,0);")?;
        Ok(Self { db })
    }
    pub fn append(&mut self, s: &Sample) -> Result<()> {
        ensure!(
            s.values.len() <= 1024
                && s.values
                    .iter()
                    .all(|(k, v)| k.len() <= 128 && v.is_finite()),
            "Metric sample exceeds bounds"
        );
        let tx = self.db.transaction()?;
        for (name, v) in &s.values {
            tx.execute(
                "INSERT OR REPLACE INTO samples VALUES(0,?1,?2,?3,?3,?3,1)",
                params![s.at, name, v],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO latest VALUES(1,?1)",
            [serde_json::to_string(s)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn latest(&self) -> Result<Option<Sample>> {
        let raw: Option<String> = self
            .db
            .query_row("SELECT body FROM latest WHERE id=1", [], |r| r.get(0))
            .optional()?;
        raw.map(|v| Ok(serde_json::from_str(&v)?)).transpose()
    }
    pub fn query(&self, name: &str, since: i64, until: i64, limit: usize) -> Result<Vec<Point>> {
        ensure!(
            name.len() <= 128
                && since >= 0
                && until > since
                && until.saturating_sub(since) <= 316224000
                && (1..=2000).contains(&limit),
            "Invalid metric query"
        );
        let bucket = ((until - since) / limit as i64).max(10);
        let mut q=self.db.prepare("SELECT (at/?4)*?4,SUM(total)/SUM(n),MIN(low),MAX(high),SUM(n),MAX(CASE tier WHEN 0 THEN 10 WHEN 1 THEN 60 WHEN 2 THEN 900 ELSE 3600 END) FROM samples WHERE name=?1 AND at>=?2 AND at<=?3 GROUP BY at/?4 ORDER BY at/?4 LIMIT ?5")?;
        Ok(
            q.query_map(params![name, since, until, bucket, limit as i64], |r| {
                Ok(Point {
                    at: r.get(0)?,
                    average: r.get(1)?,
                    min: r.get(2)?,
                    max: r.get(3)?,
                    samples: r.get(4)?,
                    resolution: r.get::<_, i64>(5)?.max(bucket),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        )
    }
    pub fn compact(&mut self, now: i64, policy: &Policy) -> Result<()> {
        policy.validate()?;
        let tx = self.db.transaction()?;
        for (tier, age, width) in [(0, 86400, 60), (1, 604800, 900), (2, 7776000, 3600)] {
            tx.execute("INSERT INTO samples SELECT ?1+1,(at/?3)*?3,name,SUM(total),MIN(low),MAX(high),SUM(n) FROM samples WHERE tier=?1 AND at<?2 GROUP BY at/?3,name ON CONFLICT(tier,at,name) DO UPDATE SET total=total+excluded.total,low=MIN(low,excluded.low),high=MAX(high,excluded.high),n=n+excluded.n",params![tier,now-age,width])?;
            tx.execute(
                "DELETE FROM samples WHERE tier=?1 AND at<?2",
                params![tier, now - age],
            )?;
        }
        tx.execute(
            "DELETE FROM samples WHERE at<?1",
            [now - i64::from(policy.days) * 86400],
        )?;
        tx.commit()?;
        // Keep the DB reusable: deleted pages are reused instead of a blocking VACUUM.
        let used:i64=self.db.query_row("SELECT (page_count-freelist_count)*page_size FROM pragma_page_count(),pragma_freelist_count(),pragma_page_size()",[],|r|r.get(0))?;
        if used as u64 > policy.budget_bytes {
            self.db.execute("DELETE FROM samples WHERE (tier,at,name) IN (SELECT tier,at,name FROM samples ORDER BY at LIMIT MAX(1000,(SELECT COUNT(*)/10 FROM samples)))",[])?;
            self.db.execute("UPDATE health SET trimmed=trimmed+1", [])?;
        }
        self.db.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
        Ok(())
    }
    pub fn health(&self) -> Result<i64> {
        Ok(self
            .db
            .query_row("SELECT trimmed FROM health WHERE id=1", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_and_rollup_keep_peaks() -> Result<()> {
        let t = tempfile::tempdir()?;
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700))?;
        let mut h = History::open(t.path())?;
        let now = 1000000;
        for (at, v) in [
            (now - 100000, 10.0),
            (now - 99990, 90.0),
            (now - 900000, 50.0),
        ] {
            h.append(&Sample {
                at,
                boot_id: "fixture".into(),
                values: BTreeMap::from([("cpu.percent".into(), v)]),
            })?;
        }
        h.compact(
            now,
            &Policy {
                days: 2,
                ..Policy::default()
            },
        )?;
        let rows = h.query("cpu.percent", now - 172800, now, 10)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].max, 90.0);
        assert_eq!(rows[0].samples, 2);
        h.compact(
            now,
            &Policy {
                days: 2,
                ..Policy::default()
            },
        )?;
        assert_eq!(h.query("cpu.percent", now - 172800, now, 10)?[0].samples, 2);
        Ok(())
    }
    #[test]
    fn counter_reset_and_outage_are_gaps() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("sys/kernel/random")).unwrap();
        fs::write(t.path().join("sys/kernel/random/boot_id"), "boot").unwrap();
        let mut c = Collector::default();
        fs::write(t.path().join("stat"), "cpu 100 0 0 100 0 0 0 0").unwrap();
        assert!(!c.sample(t.path(), 100).values.contains_key("cpu.percent"));
        fs::write(t.path().join("stat"), "cpu 150 0 0 150 0 0 0 0").unwrap();
        assert_eq!(c.sample(t.path(), 110).values["cpu.percent"], 50.0);
        assert!(!c.sample(t.path(), 200).values.contains_key("cpu.percent"));
        fs::write(t.path().join("stat"), "cpu 1 0 0 1").unwrap();
        assert!(!c.sample(t.path(), 210).values.contains_key("cpu.percent"));
    }
}
