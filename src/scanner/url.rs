use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAuditResult {
    pub url: String,
    pub domain: String,
    pub risk_score: u32, // 0 to 100
    pub is_phishing: bool,
    pub detected_threats: Vec<String>,
    pub clean_explanation_en: String,
    pub clean_explanation_hi: String,
}

pub fn scan_url(raw_url: &str) -> UrlAuditResult {
    let mut risk_score: u32 = 0;
    let mut threats = Vec::new();
    let lower_url = raw_url.to_lowercase();

    // Extract basic domain
    let domain = extract_domain(&lower_url);

    // 1. Homoglyph / Punycode check
    if domain.contains("xn--") {
        risk_score += 45;
        threats.push("Punycode / Homoglyph character spoofing detected".to_string());
    }

    // 2. High-risk TLDs commonly abused for drainers and phishing
    let suspicious_tlds = [".xyz", ".top", ".click", ".cam", ".cc", ".link", ".zip", ".buzz", ".sbs", ".quest", ".cfd"];
    for tld in &suspicious_tlds {
        if domain.ends_with(tld) {
            risk_score += 25;
            threats.push(format!("High-risk TLD ('{}') commonly used for transient throwaway phishing", tld));
            break;
        }
    }

    // 3. Brand Typosquatting / Impersonation
    let monitored_brands = [
        ("binance", &["binance-", "binanceclaim", "binance-airdrop", "binancee", "binanceverify"][..]),
        ("metamask", &["metamaskk", "metamask-auth", "metamask-verify", "metamaskio", "metamask-sync"][..]),
        ("phantom", &["phantom-claim", "phantom-app", "phantom-airdrop", "phantomwallet"][..]),
        ("stellar", &["stellardrop", "stellar-airdrop", "stellarpool", "stellar-claim", "stellar-bonus"][..]),
        ("uniswap", &["uniswap-v4", "uniswapclaim", "uniswapp", "app-uniswap"][..]),
        ("telegram", &["telegram-bot", "telegram-gift", "t-gram", "tg-stars"][..]),
        ("upwork", &["upwork-client", "upwork-pay", "upwork-verify"][..]),
        ("github", &["github-auth", "github-secure", "githubb"][..]),
    ];

    for (legit_brand, fake_patterns) in &monitored_brands {
        for pattern in *fake_patterns {
            if domain.contains(pattern) && !domain.ends_with(&format!("{}.com", legit_brand)) && !domain.ends_with(&format!("{}.io", legit_brand)) {
                risk_score += 50;
                threats.push(format!("Brand impersonation targeting '{}' via domain pattern '{}'", legit_brand, pattern));
                break;
            }
        }
    }

    // 4. Phishing Keywords in URL path or subdomain
    let scam_keywords = [
        ("airdrop", 25),
        ("claim", 25),
        ("seed-phrase", 60),
        ("privatekey", 60),
        ("secret-key", 60),
        ("connect-wallet", 20),
        ("giveaway", 30),
        ("free-crypto", 35),
        ("telegram-gift", 35),
        ("bonus-reward", 25),
        ("drainer", 70),
        ("sync-wallet", 40),
    ];

    for (kw, points) in &scam_keywords {
        if lower_url.contains(kw) {
            risk_score += points;
            threats.push(format!("High-risk scam/phishing trigger keyword '{}'", kw));
        }
    }

    // Cap score at 100
    if risk_score > 100 {
        risk_score = 100;
    }

    let is_phishing = risk_score >= 50;

    let (clean_en, clean_hi) = if is_phishing {
        (
            format!("CRITICAL PHISHING RISK: Domain '{}' exhibits deceptive impersonation patterns intended to drain credentials or crypto keys.", domain),
            format!("KHATRA! Domain '{}' ek nakli phishing link hai jo aapke crypto keys ya paise churane ke liye banayi gayi hai. Is par click bilkul na karein!", domain)
        )
    } else if risk_score > 15 {
        (
            format!("SUSPICIOUS LINK: Domain '{}' has elevated risk markers. Exercise extreme caution before connecting wallets or entering passwords.", domain),
            format!("SAVDHAAN: Domain '{}' par shaq hai. Kisi bhi tarah ka password ya wallet connect karne se pehle verify karein.", domain)
        )
    } else {
        (
            format!("LOW RISK: Domain '{}' appears legitimate with standard reputation indicators.", domain),
            format!("SAFE: Domain '{}' standard aur safe lag raha hai. Koi malicious threat detect nahi hua.", domain)
        )
    };

    UrlAuditResult {
        url: raw_url.to_string(),
        domain,
        risk_score,
        is_phishing,
        detected_threats: threats,
        clean_explanation_en: clean_en,
        clean_explanation_hi: clean_hi,
    }
}

fn extract_domain(url: &str) -> String {
    let clean = url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");
    clean.split('/').next().unwrap_or(clean).to_string()
}
