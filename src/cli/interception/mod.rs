use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use traffic_e2e::DEFAULT_FAKE_CIDR;

use super::output::{stderr_line, stdout_line};

mod dns;
mod fake_ip;

pub(super) const FIXED_USER: &str = "trp-record";

#[derive(Debug, Args)]
pub(super) struct InterceptionArgs {
    #[command(subcommand)]
    command: InterceptionCommand,
}

#[derive(Debug, Subcommand)]
enum InterceptionCommand {
    /// Manage fixed-user local DNS capture rules.
    Dns(DnsArgs),
    /// Manage fixed-user fake-IP redirect rules.
    FakeIp(FakeIpArgs),
    /// Print the fixed interception identity.
    Identity,
}

#[derive(Debug, Clone, Args)]
struct DnsArgs {
    #[command(subcommand)]
    action: RuleAction,
    #[arg(long, global = true, default_value = "127.0.0.153")]
    dns_ip: String,
    #[arg(long, global = true, default_value_t = 15353)]
    dns_port: u16,
}

#[derive(Debug, Clone, Args)]
struct FakeIpArgs {
    #[command(subcommand)]
    action: RuleAction,
    #[arg(long, global = true, default_value = DEFAULT_FAKE_CIDR)]
    fake_cidr: String,
    #[arg(long, global = true, default_value_t = 15001)]
    tcp_port: u16,
    #[arg(long, global = true, default_value_t = 15002)]
    udp_port: u16,
    #[arg(
        long,
        global = true,
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    tcp: bool,
    #[arg(
        long,
        global = true,
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    udp: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum RuleAction {
    Up,
    Down,
    Status,
}

#[derive(Debug, Clone)]
pub(super) struct DnsConfig {
    pub(super) dns_ip: String,
    pub(super) dns_port: u16,
}

#[derive(Debug, Clone)]
pub(super) struct FakeIpConfig {
    pub(super) fake_cidr: String,
    pub(super) tcp_port: u16,
    pub(super) udp_port: u16,
    pub(super) tcp: bool,
    pub(super) udp: bool,
}

pub(super) struct Guard {
    dns: DnsConfig,
    fake_ip: FakeIpConfig,
    dns_up: bool,
    fake_ip_up: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct ActiveRules {
    dns: bool,
    fake_ip: bool,
}

impl Guard {
    pub(super) fn enable(dns: DnsConfig, fake_ip: FakeIpConfig) -> Result<Self> {
        let uid = fixed_user_uid()?;
        ensure_controller_not_fixed_user(effective_uid(), uid)?;
        stderr_line(format_args!(
            "local interception owner filter enabled: {FIXED_USER} (uid {uid})"
        ));
        let mut guard = Self {
            dns,
            fake_ip,
            dns_up: false,
            fake_ip_up: false,
        };
        guard.run_root_dns(RuleAction::Up)?;
        guard.dns_up = true;
        if let Err(error) = guard.run_root_fake_ip(RuleAction::Up) {
            guard.disable();
            return Err(error);
        }
        guard.fake_ip_up = true;
        Ok(guard)
    }

    pub(super) fn disable(&mut self) {
        let active = self.take_active_rules();
        if active.fake_ip
            && let Err(error) = self.run_root_fake_ip(RuleAction::Down)
        {
            stderr_line(format_args!(
                "failed to remove fake-IP interception: {error:#}"
            ));
        }
        if active.dns
            && let Err(error) = self.run_root_dns(RuleAction::Down)
        {
            stderr_line(format_args!("failed to remove DNS interception: {error:#}"));
        }
    }

    fn take_active_rules(&mut self) -> ActiveRules {
        ActiveRules {
            dns: std::mem::take(&mut self.dns_up),
            fake_ip: std::mem::take(&mut self.fake_ip_up),
        }
    }

    fn run_root_dns(&self, action: RuleAction) -> Result<()> {
        if effective_uid() == 0 {
            return run_dns(action, &self.dns);
        }
        let args = [
            OsString::from("diagnose"),
            OsString::from("interception"),
            OsString::from("dns"),
            OsString::from(action.as_str()),
            OsString::from("--dns-ip"),
            OsString::from(&self.dns.dns_ip),
            OsString::from("--dns-port"),
            OsString::from(self.dns.dns_port.to_string()),
        ];
        run_self_as_root(&args)
    }

    fn run_root_fake_ip(&self, action: RuleAction) -> Result<()> {
        if effective_uid() == 0 {
            return run_fake_ip(action, &self.fake_ip);
        }
        let args = [
            OsString::from("diagnose"),
            OsString::from("interception"),
            OsString::from("fake-ip"),
            OsString::from(action.as_str()),
            OsString::from("--fake-cidr"),
            OsString::from(&self.fake_ip.fake_cidr),
            OsString::from("--tcp-port"),
            OsString::from(self.fake_ip.tcp_port.to_string()),
            OsString::from("--udp-port"),
            OsString::from(self.fake_ip.udp_port.to_string()),
            OsString::from("--tcp"),
            OsString::from(self.fake_ip.tcp.to_string()),
            OsString::from("--udp"),
            OsString::from(self.fake_ip.udp.to_string()),
        ];
        run_self_as_root(&args)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.disable();
    }
}

impl RuleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Status => "status",
        }
    }
}

pub(super) fn run(args: InterceptionArgs) -> Result<()> {
    match args.command {
        InterceptionCommand::Dns(args) => {
            require_root()?;
            run_dns(
                args.action,
                &DnsConfig {
                    dns_ip: args.dns_ip,
                    dns_port: args.dns_port,
                },
            )
        }
        InterceptionCommand::FakeIp(args) => {
            require_root()?;
            run_fake_ip(
                args.action,
                &FakeIpConfig {
                    fake_cidr: args.fake_cidr,
                    tcp_port: args.tcp_port,
                    udp_port: args.udp_port,
                    tcp: args.tcp,
                    udp: args.udp,
                },
            )
        }
        InterceptionCommand::Identity => {
            stdout_line(format_args!("{FIXED_USER} {}", fixed_user_uid()?))
        }
    }
}

fn run_dns(action: RuleAction, config: &DnsConfig) -> Result<()> {
    match action {
        RuleAction::Up => dns::up(config),
        RuleAction::Down => dns::down(config),
        RuleAction::Status => dns::status(config),
    }
}

fn run_fake_ip(action: RuleAction, config: &FakeIpConfig) -> Result<()> {
    match action {
        RuleAction::Up => fake_ip::up(config),
        RuleAction::Down => fake_ip::down(config),
        RuleAction::Status => fake_ip::status(config),
    }
}

pub(super) fn fixed_user_uid() -> Result<u32> {
    let output = checked_output("id", ["-u", FIXED_USER]).map_err(|error| {
        anyhow::anyhow!(
            "traffic interception user not found: {FIXED_USER}\n\
             Create it with:\n  sudo useradd --system --create-home --shell /bin/bash \
             {FIXED_USER}\n{error:#}"
        )
    })?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .context("fixed interception user has a non-numeric UID")
}

pub(super) fn fixed_user_gid() -> Result<u32> {
    let output = checked_output("id", ["-g", FIXED_USER])?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .context("fixed interception user has a non-numeric GID")
}

pub(super) fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn ensure_controller_not_fixed_user(controller_uid: u32, fixed_uid: u32) -> Result<()> {
    ensure!(
        controller_uid != fixed_uid,
        "traffic-e2e interception controller must not run as {FIXED_USER} (uid {fixed_uid}); \
         run Recorder or Replay as root or a developer account and reserve {FIXED_USER} for the \
         dependency-producing Source or Target process"
    );
    Ok(())
}

pub(super) fn checked_status<I, S>(program: &str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    let status = Command::new(system_program(program)?)
        .args(&args)
        .status()
        .with_context(|| format!("failed to run {program}"))?;
    ensure!(
        status.success(),
        "{} exited with {}",
        display_command(program, &args),
        status
    );
    Ok(())
}

pub(super) fn checked_output<I, S>(program: &str, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    let output = Command::new(system_program(program)?)
        .args(&args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    ensure!(
        output.status.success(),
        "{} exited with {}: {}",
        display_command(program, &args),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

pub(super) fn status_success<I, S>(program: &str, args: I) -> Result<bool>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Ok(Command::new(system_program(program)?)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("failed to run {program}"))?
        .success())
}

fn run_self_as_root(args: &[OsString]) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve traffic-e2e binary")?;
    let sudo = system_program("sudo")?;
    let true_command = system_program("true")?;
    ensure!(
        Command::new(&sudo)
            .arg("-n")
            .arg(true_command)
            .status()
            .context("sudo is required for local interception")?
            .success(),
        "non-interactive sudo permission is required for local interception"
    );
    let status = Command::new(sudo)
        .arg("-n")
        .arg("--")
        .arg(executable)
        .args(args)
        .env_remove("BASH_ENV")
        .env_remove("ENV")
        .env_remove("OWNER_UID")
        .status()
        .context("failed to run traffic-e2e interception setup with sudo")?;
    ensure!(
        status.success(),
        "traffic-e2e interception setup exited with {status}"
    );
    Ok(())
}

fn require_root() -> Result<()> {
    if effective_uid() != 0 {
        bail!("interception rule management must run as root");
    }
    Ok(())
}

fn display_command(program: &str, args: &[OsString]) -> String {
    std::iter::once(OsString::from(program))
        .chain(args.iter().cloned())
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn temp_root() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

pub(super) fn system_program(name: &str) -> Result<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("required system command not found: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabling_guard_clears_state_before_cleanup() {
        let mut guard = Guard {
            dns: DnsConfig {
                dns_ip: "127.0.0.153".to_string(),
                dns_port: 15353,
            },
            fake_ip: FakeIpConfig {
                fake_cidr: "198.18.0.0/15".to_string(),
                tcp_port: 15001,
                udp_port: 15002,
                tcp: true,
                udp: true,
            },
            dns_up: true,
            fake_ip_up: true,
        };

        let active = guard.take_active_rules();

        assert_eq!(
            active,
            ActiveRules {
                dns: true,
                fake_ip: true
            }
        );
        assert!(!guard.fake_ip_up);
        assert!(!guard.dns_up);
    }

    #[test]
    fn rejects_fixed_user_as_interception_controller() {
        let error = ensure_controller_not_fixed_user(998, 998)
            .unwrap_err()
            .to_string();

        assert!(error.contains("must not run as trp-record"));
        assert!(error.contains("uid 998"));
    }

    #[test]
    fn accepts_separate_interception_controller() {
        assert!(ensure_controller_not_fixed_user(0, 998).is_ok());
        assert!(ensure_controller_not_fixed_user(1000, 998).is_ok());
    }
}
