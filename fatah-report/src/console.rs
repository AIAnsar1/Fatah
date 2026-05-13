use async_trait::async_trait;
use fatah_core::{Attempt, AttemptOutcome, EngineEvent};
use owo_colors::OwoColorize;

use crate::Reporter;

/// Human-friendly stdout reporter. Colour is on by default; pass
/// `with_color(false)` for pipe-safe output.
pub struct ConsoleReporter {
    color: bool,
    verbose: bool,
}

impl Default for ConsoleReporter {
    fn default() -> Self {
        Self {
            color: true,
            verbose: false,
        }
    }
}

impl ConsoleReporter {
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    fn print_attempt(&self, a: &Attempt) {
        let login = a.credential.login_str().unwrap_or("-");
        let target = format!("{}/{}", a.target.endpoint, a.target.protocol);
        let line = match &a.outcome {
            AttemptOutcome::Success => format!("[+] {target} {login} (HIT)"),
            AttemptOutcome::Failure => format!("[-] {target} {login}"),
            AttemptOutcome::Locked => format!("[!] {target} {login} locked"),
            AttemptOutcome::RateLimited => format!("[~] {target} {login} rate-limited"),
            AttemptOutcome::Error(e) => format!("[?] {target} {login} error: {e}"),
        };
        if self.color {
            match a.outcome {
                AttemptOutcome::Success => println!("{}", line.green().bold()),
                AttemptOutcome::Failure => {
                    if self.verbose {
                        println!("{}", line.dimmed());
                    }
                }
                AttemptOutcome::Locked | AttemptOutcome::RateLimited => {
                    println!("{}", line.yellow());
                }
                AttemptOutcome::Error(_) => println!("{}", line.red()),
            }
        } else if self.verbose || !matches!(a.outcome, AttemptOutcome::Failure) {
            println!("{line}");
        }
    }
}

#[async_trait]
impl Reporter for ConsoleReporter {
    async fn on_event(&self, event: &EngineEvent) {
        match event {
            EngineEvent::Started { plan_id } => {
                println!("[*] fatah engine starting (plan {plan_id})");
            }
            EngineEvent::AttemptCompleted(a) | EngineEvent::Found(a) => self.print_attempt(a),
            EngineEvent::Progress { tried, total } => {
                if self.verbose {
                    match total {
                        Some(t) => println!("[*] progress {tried}/{t}"),
                        None => println!("[*] progress {tried}"),
                    }
                }
            }
            EngineEvent::Finished { tried, found } => {
                println!("[*] finished — tried {tried}, found {found}");
            }
            EngineEvent::Warning(w) => println!("[!] {w}"),
        }
    }
}
