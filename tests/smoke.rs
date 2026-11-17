use std::process::Command;

#[test]
#[ignore = "requires outbound public DoH access; optional RDNS_TEST_UPSTREAM_PROXY"]
fn live_doh_dnssec_and_ech() {
    let result = Command::new("python3")
        .arg("tests/doh_live.py")
        .env("RDNS_BIN", env!("CARGO_BIN_EXE_rdns"))
        .status()
        .expect("launch live DoH check");
    assert!(result.success(), "live DoH check failed");
}

#[test]
fn forwarding_access_geoip_and_gfwlist() {
    let result = Command::new("python3")
        .arg("tests/features_smoke.py")
        .env("RDNS_BIN", env!("CARGO_BIN_EXE_rdns"))
        .status()
        .expect("launch feature smoke script");
    assert!(result.success(), "feature smoke script failed");
}

#[test]
fn local_runtime_protocols_and_certificate_reload() {
    run_smoke(false, false);
}

#[test]
fn default_and_live_listener_management() {
    let result = Command::new("python3")
        .arg("tests/smoke.py")
        .env("RDNS_BIN", env!("CARGO_BIN_EXE_rdns"))
        .env("RDNS_LISTENER_TEST", "1")
        .status()
        .expect("launch listener smoke script");
    assert!(result.success(), "listener smoke script failed");
}

#[test]
#[ignore = "requires outbound DNS access to authoritative servers"]
fn live_root_dnssec_and_ech() {
    run_smoke(true, false);
}

#[test]
#[ignore = "requires a prior release build"]
fn release_binary_protocols() {
    run_smoke(false, true);
}

#[test]
#[ignore = "optional visual inspection of embedded console"]
fn console_screenshot() {
    let result = Command::new("python3")
        .arg("tests/smoke.py")
        .env("RDNS_BIN", env!("CARGO_BIN_EXE_rdns"))
        .env("RDNS_DOQ_PROBE", env!("CARGO_BIN_EXE_doq_probe"))
        .env("RDNS_SCREENSHOT", "/tmp/rdns-console-dashboard.png")
        .status()
        .expect("launch screenshot smoke script");
    assert!(result.success(), "screenshot smoke script failed");
}

fn run_smoke(live: bool, release: bool) {
    let binary = if release {
        concat!(env!("CARGO_MANIFEST_DIR"), "/target/release/rdns")
    } else {
        env!("CARGO_BIN_EXE_rdns")
    };
    let result = Command::new("python3")
        .arg("tests/smoke.py")
        .env("RDNS_BIN", binary)
        .env("RDNS_DOQ_PROBE", env!("CARGO_BIN_EXE_doq_probe"))
        .env("RDNS_LIVE_DNS", if live { "1" } else { "0" })
        .status()
        .expect("launch local smoke script");
    assert!(result.success(), "local smoke script failed");
}
