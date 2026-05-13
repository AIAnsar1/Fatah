<div align="center">

```
 ███████╗ █████╗ ████████╗ █████╗ ██╗  ██╗
 ██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║  ██║
 █████╗  ███████║   ██║   ███████║███████║
 ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══██║
 ██║     ██║  ██║   ██║   ██║  ██║██║  ██║
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Async credential-auditing toolkit. Rust. 2026.**

*A modern, modular successor to THC Hydra — written in async Rust, designed for OSS.*

[![ci](https://img.shields.io/badge/ci-workflow-7c3aed?style=flat-square&logo=github-actions&logoColor=white)](.github/workflows/ci.yml)
[![rust](https://img.shields.io/badge/rust-1.94-orange?style=flat-square&logo=rust)](rust-toolchain.toml)
[![edition](https://img.shields.io/badge/edition-2024-orange?style=flat-square)](Cargo.toml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](LICENSE)
[![status](https://img.shields.io/badge/status-alpha-yellow?style=flat-square)](#roadmap)

</div>

---

```
> whoami
fatah — fast, async, extensible. zero unsafe, deny(unwrap), deny(warnings).

> mission
audit your own infrastructure. find weak credentials before someone else does.
```

> ⚠️  **Authorized use only.** Fatah is a security tool. Run it only against
> systems you own or have explicit written permission to test. Unauthorized
> use is illegal in most jurisdictions. The authors disclaim all liability.

---

## why

| | THC Hydra (2000) | **Fatah (2026)** |
|---|---|---|
| language | C, raw `pthread` | Rust, `tokio` async |
| concurrency | pthread mutex / fork | task-based, semaphore, `governor` rate-limit |
| extension | edit `hydra-mod.c`, recompile world | one struct + `inventory::submit!` |
| state | none (re-run from zero) | session checkpoint → resume from byte N |
| safety | manual buffer math | `deny(unwrap_used)`, `zeroize` secrets, no `unsafe` |
| config | flags or nothing | flags **and** TOML/YAML/JSON profiles |
| storage | text logs | sled embedded DB + JSONL event stream |

```
old school. new tools.
```

---

## features

```
[ proto ]     ftp · ssh · http-basic   (more coming — see roadmap)
[ wire  ]     async tcp + rustls (tls feature)
[ creds ]     static · file · combo · spray (with per-password window)
[ pace  ]     semaphore-bounded workers + governor rps-limit
[ obs   ]     console reporter (ansi) + jsonl event log + tracing
[ store ]     sled-backed Repository · findings · session resume
[ ext   ]     compile-time protocol registry via `inventory`
[ ergo  ]     bon-builder AttackPlan · figment profiles · clap CLI
```

---

## quick start

```bash
# clone + build
git clone <repo> fatah && cd fatah
cargo build --release -p fatah-cli
sudo cp target/release/fatah /usr/local/bin/   # optional

# what can it speak?
fatah list-protocols

# fire a single test
fatah run -t ftp://10.0.0.5 -l admin -P /usr/share/wordlists/rockyou.txt

# password spray with declarative config
fatah run --profile examples/spray.toml --db ./loot.db

# resume an interrupted run
fatah run --resume 4f1f...d5db --profile examples/spray.toml --db ./loot.db

# show recovered credentials
fatah findings --db ./loot.db
```

---

## architecture

```
   ┌────────────────────────────────────────────────────────────┐
   │  fatah-cli   (clap + figment profile loader + telemetry)   │
   └──────────────────────────┬─────────────────────────────────┘
                              │
   ┌──────────────────────────▼─────────────────────────────────┐
   │  fatah-attack   ── Engine: semaphore · rate-limit · resume │
   └─────┬───────────────────┬──────────────┬────────────┬──────┘
         │                   │              │            │
   ┌─────▼─────┐  ┌──────────▼──────┐  ┌────▼─────┐  ┌──▼──────┐
   │ fatah-    │  │  fatah-wordlist │  │ fatah-   │  │ fatah-  │
   │  proto    │  │  (CredentialSrc)│  │  report  │  │ session │
   │  + ftp    │  │  file·combo·    │  │  console │  │ resume  │
   │  + ssh    │  │  static·spray   │  │  jsonl   │  │ state   │
   │  + http   │  └─────────────────┘  └──────────┘  └────┬────┘
   └─────┬─────┘                                          │
         │                                          ┌─────▼──────┐
   ┌─────▼──────┐                                   │  fatah-    │
   │  fatah-net │   tcp · rustls · line-codec       │  database  │
   └────────────┘                                   │  Repository│
                                                    │  + sled    │
   ┌────────────┐                                   └────────────┘
   │ fatah-core │   domain: Target · Credential · Plan · Protocol
   └────────────┘
```

**Design patterns** in play: Strategy (`Protocol`, `StrategyKind`), Registry
(inventory `ProtoEntry`), Repository (sled), Observer (`Reporter`),
Adapter (`LineStream`/TLS), Factory (`CredentialSource`), Builder
(`bon::Builder` on `AttackPlan`).

**SOLID**: core knows nothing about I/O · every layer behind a trait ·
features add code, never edit it · zero circular deps.

---

## adding a protocol

That's the whole job:

```rust
use async_trait::async_trait;
use fatah_core::*;
use fatah_proto::ProtoEntry;

#[derive(Default)]
pub struct MyProtocol;

#[async_trait]
impl Protocol for MyProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        ProtocolDescriptor {
            id: "myproto",
            default_port: 1234,
            supports_tls: false,
            summary: "my custom auth probe",
        }
    }

    async fn attempt(&self, t: &Target, c: &CredentialPair, x: &AttemptContext)
        -> Result<AttemptOutcome>
    {
        // open socket, talk protocol, classify outcome
        Ok(AttemptOutcome::Failure)
    }
}

inventory::submit! { ProtoEntry { factory: || Box::new(MyProtocol) } }
```

Compile. Run `fatah list-protocols`. Done. The CLI now accepts
`-t myproto://host:1234`.

---

## profile schema

`.toml`, `.yaml`, or `.json` — figment dispatches by extension.

```toml
[target]
host = "10.0.0.5"
port = 22
protocol = "ssh"
tls = false

[plan]
concurrency = 32
timeout = "5s"
stop_on_first = true
rate = 200                       # global attempts/sec, optional

[plan.strategy]
kind = "brute-force"             # or { kind = "spray", per_password_window = "5m" }

[source]
type = "combo"                   # static · file · combo · spray
logins = "users.txt"
passwords = "rockyou.txt"
```

---

## crate map

| crate | purpose |
|---|---|
| `fatah-core`       | domain types, `Protocol` trait, `AttackPlan` builder, errors |
| `fatah-macros`     | `#[fatah_proto]` proc-attribute for third-party modules |
| `fatah-net`        | async TCP, `LineStream`, rustls TLS connector |
| `fatah-wordlist`   | `CredentialSource` + static/file/combo sources |
| `fatah-spray`      | password-spray source (outer = password, inner = logins, window-paced) |
| `fatah-database`   | `Repository` trait + embedded sled implementation |
| `fatah-session`    | resumable session state on top of any `Repository` |
| `fatah-proto`      | inventory-based protocol registry + built-in `ftp`/`ssh`/`http-basic` |
| `fatah-report`     | `Reporter` trait, console (ansi) + JSONL reporters |
| `fatah-attack`     | the engine: workers · rate-limit · checkpointing |
| `fatah-telemetry`  | `tracing-subscriber` bootstrap (pretty/compact/json) |
| `fatah-testing`    | `MockProtocol` and helpers for unit tests |
| `fatah-cli`        | the `fatah` binary |
| `benchmarks`       | criterion suite (credential streams, engine throughput) |

---

## scripts

```
scripts/check.sh         fmt --check + clippy -D warnings + test    (pre-commit)
scripts/fmt.sh           cargo fmt --all
scripts/lint.sh          cargo clippy --workspace --all-targets --all-features
scripts/test.sh          cargo test --workspace --all-features
scripts/bench.sh         cargo bench -p fatah-benchmarks
scripts/build-release.sh strip + drop into ./dist/fatah
scripts/dev-ftp.sh       up|down — throwaway FTP container on :2121
```

---

## ci

Defined in `.github/workflows/`:

- **`ci.yml`** — `fmt --check`, `clippy -D warnings`, `test` on
  ubuntu + macos, release build with artifact upload, `cargo-audit`.
- **`bench.yml`** — weekly + manual criterion run with HTML report
  artifact.

---

## roadmap

```
[x] core domain + plan/builder/strategy types
[x] inventory protocol registry + #[fatah_proto] macro
[x] ftp · ssh · http-basic modules
[x] tls transport (rustls + webpki-roots)
[x] sled Repository + session resume + jsonl reporter
[x] figment TOML/YAML/JSON profiles + clap CLI
[x] criterion benches · github actions ci

[ ] smb · rdp · mysql · postgres · ldap · redis · vnc · mongodb
[ ] socks5/http-proxy chain support
[ ] progress bar (indicatif) + ctrl-c graceful shutdown w/ final checkpoint
[ ] distributed worker mode (multi-host coordination over redis/nats)
[ ] tui dashboard (ratatui)
[ ] release binaries on github releases (linux x64/arm64, macos, windows)
```

---

## non-goals

- We will **not** ship modules whose only purpose is to evade detection
  or bypass safety controls. Authentication probes only.
- No supply-chain compromise tooling. No mass-target automation.
- If you need offensive C2 or post-exploitation, look elsewhere.

---

## contributing

PRs welcome. The bar is:

```
1. ./scripts/check.sh is green
2. new code has tests (or a clear reason it can't)
3. no new `unwrap()` — the workspace denies it
4. document non-obvious WHY in comments, not WHAT
```

---

## license

Dual-licensed under either:

- MIT — [LICENSE-MIT](LICENSE-MIT)
- Apache 2.0 — [LICENSE-APACHE](LICENSE-APACHE)

at your option.

---

<div align="center">

```
$ fatah --help
audit yourself before they audit you.
```

</div>
