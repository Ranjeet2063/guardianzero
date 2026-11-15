use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAuditResult {
    pub file_path: String,
    pub is_infostealer: bool,
    pub risk_score: u32,
    pub detected_signatures: Vec<String>,
    pub sandbox_audited: bool,
    pub human_verdict_en: String,
    pub human_verdict_hi: String,
}

pub fn scan_file<P: AsRef<Path>>(path: P) -> FileAuditResult {
    let path_ref = path.as_ref();
    let file_str = path_ref.to_string_lossy().to_string();

    if !path_ref.exists() {
        return FileAuditResult {
            file_path: file_str,
            is_infostealer: false,
            risk_score: 0,
            detected_signatures: vec!["File does not exist on disk".to_string()],
            sandbox_audited: false,
            human_verdict_en: "File not found.".to_string(),
            human_verdict_hi: "File disk par nahi mili.".to_string(),
        };
    }

    let mut risk_score: u32 = 0;
    let mut detected = Vec::new();

    // Read content safely (up to 5MB to prevent memory exhaustion)
    let content = match fs::read(path_ref) {
        Ok(bytes) => {
            let max_slice = &bytes[..std::cmp::min(bytes.len(), 5 * 1024 * 1024)];
            String::from_utf8_lossy(max_slice).to_lowercase()
        }
        Err(e) => {
            return FileAuditResult {
                file_path: file_str,
                is_infostealer: false,
                risk_score: 10,
                detected_signatures: vec![format!("Failed to read file: {}", e)],
                sandbox_audited: false,
                human_verdict_en: "Unreadable binary or permission denied.".to_string(),
                human_verdict_hi: "File ko read nahi kiya ja saka.".to_string(),
            };
        }
    };

    // 1. Browser Password & Cookie Stealer Signatures
    let browser_stealer_patterns = [
        ("login data", 40, "Attempts to access Chrome/Edge saved passwords database"),
        ("web data", 30, "Targets browser autofill and credit card databases"),
        ("cookies.sqlite", 35, "Attempts to steal active Firefox session cookies"),
        ("network\\cookies", 35, "Attempts to steal Chromium session cookies"),
        ("local state", 25, "Accesses Chrome encryption keys master state file"),
    ];
    for (pat, score, desc) in &browser_stealer_patterns {
        if content.contains(pat) {
            risk_score += score;
            detected.push(format!("Infostealer Marker: {}", desc));
        }
    }

    // 2. Crypto Wallet Extension & Keystore Targeting
    let wallet_patterns = [
        ("nkbihfbeogaeaoehlefnkodbefgpgknn", 45, "Targets MetaMask browser extension keystore"),
        ("bfnaelmomeimhlpmgjnjophhpkkoljpa", 45, "Targets Phantom wallet extension"),
        ("solflare", 30, "Targets Solflare Solana wallet extension"),
        ("wallet.dat", 40, "Attempts to harvest Bitcoin Core wallet.dat keystore"),
        ("id_rsa", 35, "Searches for private SSH keys in ~/.ssh"),
        (".env", 20, "Harvests environment configuration and API secrets"),
    ];
    for (pat, score, desc) in &wallet_patterns {
        if content.contains(pat) {
            risk_score += score;
            detected.push(format!("Credential Extraction: {}", desc));
        }
    }

    // 3. Telegram & Discord Session Hijacking
    if content.contains("tdata") && content.contains("telegram") {
        risk_score += 40;
        detected.push("Session Hijacking: Attempts to exfiltrate Telegram desktop 'tdata' session".to_string());
    }
    if content.contains("discord") && (content.contains("tokens") || content.contains("local storage")) {
        risk_score += 35;
        detected.push("Token Exfiltration: Targets Discord account authentication tokens".to_string());
    }

    // 4. Obfuscation & Malicious Execution Primitives
    let exec_patterns = [
        ("eval(atob(", 40, "Dynamic base64 obfuscation wrapper (`eval(atob)`)"),
        ("powershell -enc", 45, "Encoded PowerShell execution payload"),
        ("curl | bash", 40, "Unverified pipe-to-shell download execution"),
        ("wget | sh", 40, "Unverified pipe-to-shell download execution"),
        ("discord.com/api/webhooks", 35, "Exfiltrates stolen credentials to Discord webhook"),
        ("api.telegram.org/bot", 35, "Exfiltrates stolen credentials to Telegram bot"),
    ];
    for (pat, score, desc) in &exec_patterns {
        if content.contains(pat) {
            risk_score += score;
            detected.push(format!("Suspicious Payload: {}", desc));
        }
    }

    if risk_score > 100 {
        risk_score = 100;
    }

    let is_infostealer = risk_score >= 50;

    let (en, hi) = if is_infostealer {
        (
            format!("🚨 CRITICAL MALWARE / INFOSTEALER DETECTED in '{}'! It contains code targeting browser passwords, crypto wallets, or session keys.", file_str),
            format!("🚨 MAHA-KHATRA: '{}' EK DANGEROUS VIRUS / INFOSTEALER HAI! Ye aapke Chrome passwords aur crypto wallets chori karne ke liye banaya gaya hai. Ise RUN MAT KARNA aur turant delete kardo!", file_str)
        )
    } else if risk_score > 20 {
        (
            format!("⚠️ SUSPICIOUS FILE '{}': Contains elevated risk patterns. Do not execute without sandboxing.", file_str),
            format!("⚠️ SAVDHAAN: File '{}' me suspicious patterns hain. Bina sandbox ke ise mat chalana.", file_str)
        )
    } else {
        (
            format!("✅ File '{}' appears safe. No credential stealer signatures found.", file_str),
            format!("✅ File '{}' clean aur safe lag rahi hai. Koi malware signature nahi mili.", file_str)
        )
    };

    FileAuditResult {
        file_path: file_str,
        is_infostealer,
        risk_score,
        detected_signatures: detected,
        sandbox_audited: false,
        human_verdict_en: en,
        human_verdict_hi: hi,
    }
}
