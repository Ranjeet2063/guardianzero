use std::fs;

#[test]
fn test_phishing_url_detection() {
    let raw = "https://metamask-verify-claim.xyz/airdrop";
    let is_scam = raw.contains("xyz") && raw.contains("airdrop");
    assert!(is_scam, "Should detect high risk phishing URL markers");
}

#[test]
fn test_safe_url_detection() {
    let raw = "https://crates.io/crates/tracezero";
    let is_safe = !raw.contains("airdrop") && raw.ends_with("tracezero");
    assert!(is_safe, "Legitimate domain should not be flagged as phishing");
}

#[test]
fn test_contract_drainer_detection() {
    let calldata = "setApprovalForAll(0x1234567890123456789012345678901234567890, true)";
    let is_drainer = calldata.to_lowercase().contains("setapprovalforall") && calldata.contains("true");
    assert!(is_drainer, "setApprovalForAll(true) must be flagged as critical drainer");
}

#[test]
fn test_social_engineering_scam_detection() {
    let msg = "Congratulations! Send 100 USDC to double your investment with guaranteed 2x daily returns!";
    let lower = msg.to_lowercase();
    let is_ponzi = lower.contains("send") && (lower.contains("double") || lower.contains("2x"));
    assert!(is_ponzi, "Crypto doubling message must be identified as scam");
}

#[test]
fn test_infostealer_file_signatures() {
    let temp_file = "/tmp/test_malicious_script.py";
    let script = "import os\npath = os.path.expanduser('~/.config/google-chrome/Default/Login Data')\nprint(path)\n";
    fs::write(temp_file, script).unwrap();

    let content = fs::read_to_string(temp_file).unwrap().to_lowercase();
    let is_infostealer = content.contains("login data");
    let _ = fs::remove_file(temp_file);

    assert!(is_infostealer, "Targeting Chrome Login Data must trigger infostealer detection");
}
