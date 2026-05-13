//! Declarative attack profile loaded from TOML / YAML / JSON via
//! `figment`. The profile is intentionally separate from
//! [`AttackPlan`] in `fatah-core` — the core type is the *internal*
//! aggregate, this is the *external* schema the CLI accepts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use fatah_core::{
    AttackPlan, Credential, CredentialPair, Endpoint, RateLimit, Secret, StrategyKind, Target,
};
use fatah_spray::SpraySource;
use fatah_wordlist::{ComboSource, CredentialSource, FileWordlist, StaticSource};
use figment::Figment;
use figment::providers::{Format as _, Json, Toml, Yaml};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub target: TargetCfg,
    #[serde(default)]
    pub plan: PlanCfg,
    pub source: SourceCfg,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TargetCfg {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub options: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PlanCfg {
    #[serde(default)]
    pub strategy: StrategyKind,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,
    #[serde(default)]
    pub rate: Option<u32>,
    #[serde(default = "default_stop_on_first")]
    pub stop_on_first: bool,
}

fn default_concurrency() -> usize {
    16
}
fn default_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_stop_on_first() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SourceCfg {
    Static {
        pairs: Vec<PairCfg>,
    },
    File {
        path: PathBuf,
        login: String,
    },
    Combo {
        logins: PathBuf,
        passwords: PathBuf,
    },
    Spray {
        logins: PathBuf,
        passwords: PathBuf,
        #[serde(with = "humantime_serde", default = "default_spray_window")]
        per_password_window: Duration,
    },
}

fn default_spray_window() -> Duration {
    Duration::from_secs(300)
}

#[derive(Debug, Deserialize)]
pub struct PairCfg {
    pub login: Option<String>,
    pub secret: String,
}

impl Profile {
    /// Load a profile, dispatching on file extension. Unknown
    /// extensions are tried as TOML.
    pub fn load(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("toml")
            .to_ascii_lowercase();
        let fig = match ext.as_str() {
            "yaml" | "yml" => Figment::new().merge(Yaml::file(path)),
            "json" => Figment::new().merge(Json::file(path)),
            _ => Figment::new().merge(Toml::file(path)),
        };
        fig.extract::<Profile>()
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn target(&self) -> Target {
        let mut t = Target::new(
            Endpoint::new(self.target.host.clone(), self.target.port),
            self.target.protocol.clone(),
        )
        .with_tls(self.target.tls);
        for (k, v) in &self.target.options {
            t = t.with_option(k, v);
        }
        t
    }

    pub fn build_plan(&self) -> AttackPlan {
        let target = self.target();
        AttackPlan::builder()
            .target(target)
            .strategy(self.plan.strategy.clone())
            .concurrency(self.plan.concurrency)
            .timeout(self.plan.timeout)
            .maybe_rate(self.plan.rate.and_then(RateLimit::per_second))
            .stop_on_first(self.plan.stop_on_first)
            .build()
    }

    pub fn build_source(&self) -> Result<Box<dyn CredentialSource>> {
        Ok(match &self.source {
            SourceCfg::Static { pairs } => {
                if pairs.is_empty() {
                    bail!("source.pairs is empty");
                }
                let pairs = pairs
                    .iter()
                    .map(|p| CredentialPair {
                        login: p.login.clone().map(Credential::from),
                        secret: Secret::new(p.secret.clone()),
                    })
                    .collect();
                Box::new(StaticSource::new(pairs))
            }
            SourceCfg::File { path, login } => {
                Box::new(FileWordlist::passwords_for(path, login.clone()))
            }
            SourceCfg::Combo { logins, passwords } => {
                Box::new(ComboSource::new(logins.clone(), passwords.clone()))
            }
            SourceCfg::Spray {
                logins,
                passwords,
                per_password_window,
            } => Box::new(SpraySource::new(
                logins.clone(),
                passwords.clone(),
                *per_password_window,
            )),
        })
    }
}

// Suppress unused-import lint when only some serde features are exercised.
const _: fn() = || {
    let _ = std::marker::PhantomData::<TargetCfg>;
    let _ = std::marker::PhantomData::<PlanCfg>;
};
