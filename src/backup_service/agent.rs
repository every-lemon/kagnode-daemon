//! Outbound client; one immutable signed snapshot can be pushed to every enrolled server.
use super::{
    repository::{Lease, SignedSnapshot},
    transport::{Enrollment, NodeRequest, read_file},
};
use anyhow::{Result, ensure};
use base64::Engine;
use kagnode_backup_format::{Manifest, digest, identifier, read_object};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub site: String,
    pub server: String,
    pub endpoint: String,
    pub ca: PathBuf,
    pub identity_pem: PathBuf,
}
pub struct Agent {
    node: String,
    key: Ed25519KeyPair,
    client: reqwest::Client,
    target: Target,
}
impl Agent {
    pub fn new(node: &str, key: Ed25519KeyPair, target: Target) -> Result<Self> {
        ensure!(
            [node, &target.site, &target.server]
                .iter()
                .all(|v| identifier(v)),
            "Invalid backup identity"
        );
        let url = reqwest::Url::parse(&target.endpoint)?;
        ensure!(
            url.scheme() == "https"
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "Use an HTTPS origin without credentials, paths or queries"
        );
        let ca = reqwest::Certificate::from_pem(&read_file(&target.ca, false)?)?;
        let identity = zeroize::Zeroizing::new(read_file(&target.identity_pem, true)?);
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(reqwest::Identity::from_pem(&identity)?)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            node: node.into(),
            key,
            client,
            target,
        })
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.key.public_key().as_ref())
    }
    pub async fn enroll(&self, token: &str) -> Result<()> {
        ensure!(token.len() <= 128, "Invalid enrollment token");
        let message = format!(
            "kagnode-backup-enroll/v1\n{}\n{}\n{}\n{token}",
            self.target.site, self.target.server, self.node
        );
        let value = Enrollment {
            node: self.node.clone(),
            token: token.into(),
            proof: hex::encode(self.key.sign(message.as_bytes()).as_ref()),
        };
        let response = self
            .client
            .post(format!(
                "{}/api/v1/backup-server/enroll",
                self.target.endpoint.trim_end_matches('/')
            ))
            .json(&value)
            .send()
            .await?;
        ensure!(response.status().is_success(), "Enrollment refused");
        Ok(())
    }
    async fn call(&self, request: &NodeRequest) -> Result<Value> {
        let body = serde_json::to_vec(request)?;
        let nonce = crate::auth::random()?;
        let at = crate::auth::now();
        let message = format!(
            "kagnode-backup-request/v1\n{}\n{}\n{}\n{nonce}\n{at}\nnode\n{}",
            self.target.site,
            self.target.server,
            self.node,
            digest(&body)
        );
        let mut response = self
            .client
            .post(format!(
                "{}/api/v1/backup-server/node",
                self.target.endpoint.trim_end_matches('/')
            ))
            .header("content-type", "application/json")
            .header("x-kagnode-node", &self.node)
            .header("x-kagnode-nonce", nonce)
            .header("x-kagnode-time", at)
            .header(
                "x-kagnode-signature",
                hex::encode(self.key.sign(message.as_bytes()).as_ref()),
            )
            .body(body)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "Backup request refused (HTTP {})",
            response.status()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 10 * 1024 * 1024,
                "Response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(value["ok"] == true, "Backup request did not succeed");
        Ok(value["value"].clone())
    }
    pub async fn status(&self) -> Result<Value> {
        self.call(&NodeRequest::Status).await
    }
    /// Returns a ciphertext receipt. This is not evidence of plaintext recovery or an independent restore test.
    pub async fn push(&self, manifest: Manifest, objects: &Path) -> Result<Value> {
        ensure!(
            manifest.node == self.node && manifest.site == self.target.site,
            "Snapshot identity mismatch"
        );
        let signature = hex::encode(self.key.sign(&manifest.bytes()?).as_ref());
        let lease: Lease = serde_json::from_value(
            self.call(&NodeRequest::Begin {
                snapshot: SignedSnapshot {
                    manifest,
                    signature,
                },
            })
            .await?,
        )?;
        let mut renewed = std::time::Instant::now();
        for object in lease.missing {
            let bytes = read_object(objects, &object)?;
            let offset = self
                .call(&NodeRequest::Offset {
                    lease: lease.id.clone(),
                    object: object.sha256.clone(),
                })
                .await?["offset"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Invalid upload offset"))?;
            ensure!(offset <= object.bytes, "Server offset exceeds object size");
            let mut offset = offset as usize;
            while offset < bytes.len() {
                if renewed.elapsed() >= Duration::from_secs(300) {
                    self.call(&NodeRequest::Renew {
                        lease: lease.id.clone(),
                    })
                    .await?;
                    renewed = std::time::Instant::now();
                }
                let end = (offset + 1024 * 1024).min(bytes.len());
                let reply = self
                    .call(&NodeRequest::Upload {
                        lease: lease.id.clone(),
                        object: object.sha256.clone(),
                        offset: offset as u64,
                        data: base64::engine::general_purpose::STANDARD.encode(&bytes[offset..end]),
                    })
                    .await?;
                ensure!(
                    reply["offset"] == end as u64,
                    "Unexpected upload acknowledgment"
                );
                offset = end;
            }
        }
        self.call(&NodeRequest::Finish { lease: lease.id }).await
    }
}
/// Independent failures do not discard success elsewhere. Input manifest is reused unchanged.
pub async fn push_all(agents: &[Agent], manifest: &Manifest, objects: &Path) -> Vec<Value> {
    let mut receipts = Vec::new();
    for agent in agents {
        let result = agent.push(manifest.clone(), objects).await;
        receipts.push(match result {
            Ok(receipt) => json!({"server":agent.target.server,"ok":true,"receipt":receipt}),
            Err(error) => {
                json!({"server":agent.target.server,"ok":false,"error":error.to_string()})
            }
        });
    }
    receipts
}
