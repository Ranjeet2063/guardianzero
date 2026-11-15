use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAuditResult {
    pub message_snippet: String,
    pub is_social_engineering: bool,
    pub risk_score: u32,
    pub detected_traps: Vec<String>,
    pub human_advice_en: String,
    pub human_advice_hi: String,
}

pub fn scan_social_message(text: &str) -> SocialAuditResult {
    let mut risk_score: u32 = 0;
    let mut traps = Vec::new();
    let lower = text.to_lowercase();

    // 1. Secret Key & Recovery Phrase Extraction Triggers
    if lower.contains("seed phrase") || lower.contains("secret key") || lower.contains("12 words") || lower.contains("24 words") || lower.contains("private key") {
        risk_score += 90;
        traps.push("Direct Credential Theft: Requests your seed phrase or private keys (NO legitimate admin or platform ever asks this!)".to_string());
    }

    // 2. Crypto Doubling / Ponzi Returns
    if (lower.contains("send") || lower.contains("deposit")) && (lower.contains("double") || lower.contains("2x") || lower.contains("guaranteed profit") || lower.contains("daily returns")) {
        risk_score += 85;
        traps.push("Ponzi / Doubling Scam: Guarantees multiplied returns on initial crypto deposits".to_string());
    }

    // 3. Fake Freelance / Upwork / Telegram Job Malware Bait
    if (lower.contains("test this game") || lower.contains("download the build") || lower.contains("run this demo") || lower.contains("github repo has issue")) && (lower.contains("pay") || lower.contains("$500") || lower.contains("$1000") || lower.contains("budget")) {
        risk_score += 70;
        traps.push("Fake Recruiter Malware Bait: Prompts target to download and execute untrusted files under the guise of paid testing".to_string());
    }

    // 4. Artificial Fear & Panic Urgency
    if (lower.contains("suspended") || lower.contains("blocked") || lower.contains("law enforcement") || lower.contains("account closed")) && (lower.contains("within 24 hours") || lower.contains("immediately") || lower.contains("urgent action")) {
        risk_score += 60;
        traps.push("Psychological Pressure: Uses artificial fear and urgent deadlines to force impulsive, unverified actions".to_string());
    }

    // 5. Lottery / Unearned Giveaway Bait
    if (lower.contains("you have won") || lower.contains("selected as winner") || lower.contains("claim your gift")) && (lower.contains("click here") || lower.contains("connect")) {
        risk_score += 55;
        traps.push("Unsolicited Prize Bait: Exploits lottery/winner claims to lure users into phishing portals".to_string());
    }

    if risk_score > 100 {
        risk_score = 100;
    }

    let is_scam = risk_score >= 50;

    let (en, hi) = if is_scam {
        (
            "🚨 CRITICAL SCAM / FRAUD DETECTED! This message uses known cyber-criminal deception tactics. Do not reply, do not send money, and do not download any files!".to_string(),
            "🚨 MAHA-FRAUD ALERT! Ye 100% SCAM MESSAGE hai! Scammer aapke paise ya passwords churane ke liye jhoot bol raha hai. Koi reply mat do aur koi file download mat karna!".to_string(),
        )
    } else if risk_score > 20 {
        (
            "⚠️ SUSPICIOUS PATTERNS: The message contains urgency or financial triggers. Verify identity through official channels.".to_string(),
            "⚠️ SAVDHAAN: Is message me thoda shaq hai. Kisi bhi anjaan insaan par bharosa na karein.".to_string(),
        )
    } else {
        (
            "✅ Message appears low risk. No social engineering triggers detected.".to_string(),
            "✅ Message normal lag raha hai. Koi scam pattern nahi mila.".to_string(),
        )
    };

    let snippet = if text.len() > 80 {
        format!("{}...", &text[..80])
    } else {
        text.to_string()
    };

    SocialAuditResult {
        message_snippet: snippet,
        is_social_engineering: is_scam,
        risk_score,
        detected_traps: traps,
        human_advice_en: en,
        human_advice_hi: hi,
    }
}
