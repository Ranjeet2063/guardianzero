use crate::scanner::{scan_url, scan_contract_call, scan_file, scan_social_message};
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignAuditReport {
    pub input_type: String,
    pub original_query: String,
    pub risk_level: String, // "CRITICAL", "SUSPICIOUS", "SAFE"
    pub risk_score: u32,
    pub detected_threats: Vec<String>,
    pub human_verdict_en: String,
    pub human_verdict_hi: String,
    pub recommended_action: String,
}

pub fn analyze_target(input: &str) -> SovereignAuditReport {
    let trimmed = input.trim();

    // 1. Detect if input is a local file path
    if Path::new(trimmed).exists() && (trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('.')) {
        let res = scan_file(trimmed);
        let level = if res.risk_score >= 50 { "CRITICAL" } else if res.risk_score > 20 { "SUSPICIOUS" } else { "SAFE" };
        let action = if res.risk_score >= 50 {
            "DELETE IMMEDIATELY: Do not execute, run, or open this file. It contains credential theft payloads."
        } else {
            "Verify origin: Safe to use or proceed."
        };
        return SovereignAuditReport {
            input_type: "FILE".to_string(),
            original_query: trimmed.to_string(),
            risk_level: level.to_string(),
            risk_score: res.risk_score,
            detected_threats: res.detected_signatures,
            human_verdict_en: res.human_verdict_en,
            human_verdict_hi: res.human_verdict_hi,
            recommended_action: action.to_string(),
        };
    }

    // 2. Detect if input is a URL
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.contains(".com") || trimmed.contains(".xyz") || trimmed.contains(".io") || trimmed.contains(".org") {
        let res = scan_url(trimmed);
        let level = if res.risk_score >= 50 { "CRITICAL" } else if res.risk_score > 15 { "SUSPICIOUS" } else { "SAFE" };
        let action = if res.risk_score >= 50 {
            "BLOCK & DO NOT CLICK: Close the tab immediately. Never connect crypto wallets or enter passwords."
        } else {
            "Proceed with normal security awareness."
        };
        return SovereignAuditReport {
            input_type: "URL".to_string(),
            original_query: trimmed.to_string(),
            risk_level: level.to_string(),
            risk_score: res.risk_score,
            detected_threats: res.detected_threats,
            human_verdict_en: res.clean_explanation_en,
            human_verdict_hi: res.clean_explanation_hi,
            recommended_action: action.to_string(),
        };
    }

    // 3. Detect if input is a Web3 contract method or calldata
    let lower = trimmed.to_lowercase();
    if lower.contains("approve") || lower.contains("permit") || lower.contains("setapprovalforall") || lower.contains("0x") || lower.contains("transferfrom") {
        let res = scan_contract_call(trimmed);
        let level = if res.risk_score >= 70 { "CRITICAL" } else if res.risk_score > 30 { "SUSPICIOUS" } else { "SAFE" };
        let action = if res.risk_score >= 70 {
            "REJECT TRANSACTION IMMEDIATELY: Do not sign this transaction. It is designed to sweep your tokens/NFTs."
        } else {
            "Double-check spender address before approving."
        };
        return SovereignAuditReport {
            input_type: "SMART_CONTRACT".to_string(),
            original_query: trimmed.to_string(),
            risk_level: level.to_string(),
            risk_score: res.risk_score,
            detected_threats: res.threats,
            human_verdict_en: res.human_verdict_en,
            human_verdict_hi: res.human_verdict_hi,
            recommended_action: action.to_string(),
        };
    }

    // 4. Default: Social Engineering & Chat Message Scanner
    let res = scan_social_message(trimmed);
    let level = if res.risk_score >= 50 { "CRITICAL" } else if res.risk_score > 20 { "SUSPICIOUS" } else { "SAFE" };
    let action = if res.risk_score >= 50 {
        "IGNORE & BLOCK: This message is a scam. Never send funds, seed phrases, or download suggested files."
    } else {
        "Verify identity of the sender independently."
    };
    SovereignAuditReport {
        input_type: "MESSAGE".to_string(),
        original_query: trimmed.to_string(),
        risk_level: level.to_string(),
        risk_score: res.risk_score,
        detected_threats: res.detected_traps,
        human_verdict_en: res.human_advice_en,
        human_verdict_hi: res.human_advice_hi,
        recommended_action: action.to_string(),
    }
}

pub fn print_report(report: &SovereignAuditReport) {
    println!("\n{}", "=========================================================".cyan());
    println!("{}", "🛡️  GuardianZero (g0) Sovereign Threat Assessment".bold().white());
    println!("{}", "=========================================================".cyan());
    println!("🔍 Category: {}", report.input_type.bold().yellow());
    
    let level_colored = match report.risk_level.as_str() {
        "CRITICAL" => report.risk_level.bold().red(),
        "SUSPICIOUS" => report.risk_level.bold().yellow(),
        _ => report.risk_level.bold().green(),
    };
    println!("📊 Risk Level: {} (Score: {}/100)", level_colored, report.risk_score);

    if !report.detected_threats.is_empty() {
        println!("\n{}", "⚠️  Detected Risk Indicators:".bold().red());
        for t in &report.detected_threats {
            println!("   [-] {}", t.bright_red());
        }
    }

    println!("\n{}", "💡 Human Verdict (Hinglish):".bold().cyan());
    println!("   {}", report.human_verdict_hi.white());

    println!("\n{}", "💡 Human Verdict (English):".bold().cyan());
    println!("   {}", report.human_verdict_en.white());

    println!("\n{}", "🛑 Recommended Immediate Action:".bold().yellow());
    println!("   👉 {}", report.recommended_action.bold().white());
    println!("{}\n", "=========================================================".cyan());
}
