use crate::config::Config;
use anyhow::{Context, Result};
use std::{fs, path::Path, process::Command};

const UNIT_PATH: &str = "/etc/systemd/system/rdns.service";

pub fn install(config_path: &Path) -> Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "systemd service installation requires Linux"
    );
    anyhow::ensure!(id_is_root()?, "run service install as root");
    let config_path = fs::canonicalize(config_path)
        .with_context(|| format!("finding {}", config_path.display()))?;
    let config = Config::load(&config_path)?;
    let binary = fs::canonicalize(std::env::current_exe()?)?;
    let data_dir = config
        .database
        .parent()
        .context("database path has no parent")?;
    fs::create_dir_all(data_dir)?;
    if !user_exists("rdns")? {
        command(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "rdns",
            ],
        )?;
    }
    for path in [&config_path, &binary] {
        anyhow::ensure!(path.exists(), "required file missing: {}", path.display());
        ensure_readable_by_service(path)?;
    }
    for path in [&config.certificate, &config.private_key]
        .into_iter()
        .flatten()
    {
        anyhow::ensure!(path.exists(), "required file missing: {}", path.display());
        ensure_readable_by_service(path)?;
    }
    if let Some(ca) = &config.subscription_ca {
        ensure_readable_by_service(ca)?;
    }
    if let Some(hints) = &config.root_hints {
        ensure_readable_by_service(hints)?;
    }
    ensure_writable_by_service(data_dir)?;
    let unit = unit_text(&binary, &config_path, data_dir)?;
    let unit_path = Path::new(UNIT_PATH);
    if unit_path.exists() {
        let existing = fs::read_to_string(unit_path)?;
        anyhow::ensure!(
            existing.starts_with("# Managed by rDns\n"),
            "{} exists and is not managed by rDns",
            UNIT_PATH
        );
    }
    let was_active = service_active()?;
    fs::write(unit_path, unit).with_context(|| format!("writing {UNIT_PATH}"))?;
    command("systemctl", &["daemon-reload"])?;
    command("systemctl", &["enable", "--now", "rdns.service"])?;
    if was_active {
        command("systemctl", &["restart", "rdns.service"])?;
    }
    command("systemctl", &["is-active", "--quiet", "rdns.service"])?;
    println!(
        "Installed and started rdns.service using {}",
        config_path.display()
    );
    Ok(())
}

fn unit_text(binary: &Path, config: &Path, data_dir: &Path) -> Result<String> {
    for path in [binary, config, data_dir] {
        anyhow::ensure!(
            !path.to_string_lossy().chars().any(char::is_whitespace),
            "systemd paths cannot contain whitespace: {}",
            path.display()
        );
    }
    Ok(format!(
        "# Managed by rDns\n[Unit]\nDescription=rDns recursive DNS service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=rdns\nGroup=rdns\nExecStart={} {}\nWorkingDirectory={}\nRestart=on-failure\nRestartSec=3\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths={}\nPrivateTmp=true\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n",
        binary.display(),
        config.display(),
        data_dir.display(),
        data_dir.display()
    ))
}

fn id_is_root() -> Result<bool> {
    let output = Command::new("id").arg("-u").output()?;
    Ok(output.status.success() && output.stdout == b"0\n")
}

fn user_exists(user: &str) -> Result<bool> {
    Ok(Command::new("id")
        .args(["-u", user])
        .output()?
        .status
        .success())
}

fn service_active() -> Result<bool> {
    Ok(Command::new("systemctl")
        .args(["is-active", "--quiet", "rdns.service"])
        .status()?
        .success())
}

fn ensure_readable_by_service(path: &Path) -> Result<()> {
    let status = Command::new("runuser")
        .args(["-u", "rdns", "--", "test", "-r"])
        .arg(path)
        .status()?;
    anyhow::ensure!(status.success(), "rdns user cannot read {}", path.display());
    Ok(())
}

fn ensure_writable_by_service(path: &Path) -> Result<()> {
    let status = Command::new("runuser")
        .args(["-u", "rdns", "--", "test", "-w"])
        .arg(path)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "rdns user cannot write {}",
        path.display()
    );
    Ok(())
}

fn command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("running {program}"))?;
    anyhow::ensure!(
        status.success(),
        "{program} {} failed with {status}",
        args.join(" ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    #[test]
    fn unit_points_to_absolute_config_and_data_directory() {
        let text = unit_text(
            &PathBuf::from("/opt/rDns/rdns"),
            &PathBuf::from("/opt/rDns/config.toml"),
            &PathBuf::from("/opt/rDns/data"),
        )
        .unwrap();
        assert!(text.contains("ExecStart=/opt/rDns/rdns /opt/rDns/config.toml"));
        assert!(text.contains("ReadWritePaths=/opt/rDns/data"));
    }
}
