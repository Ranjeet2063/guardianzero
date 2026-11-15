use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAuditResult {
    pub target: String,
    pub risk_score: u32,
    pub is_drainer: bool,
    pub threats: Vec<String>,
    pub human_verdict_en: String,
    pub human_verdict_hi: String,
}

pub fn scan_contract_call(calldata_or_method: &str) -> ContractAuditResult {
    let mut risk_score: u32 = 0;
    let mut threats = Vec::new();
    let lower = calldata_or_method.to_lowercase();

    // 1. ERC-721 / ERC-1155 NFT Sweeper: setApprovalForAll
    if lower.contains("setapprovalforall") || lower.contains("0xa220196a") {
        if lower.contains("true") || lower.contains("0000000000000000000000000000000000000000000000000000000000000001") {
            risk_score += 85;
            threats.push("Critical Drainer: 'setApprovalForAll(true)' grants contract full permission to drain all your NFTs!".to_string());
        }
    }

    // 2. ERC-20 Unlimited Approval: approve(spender, max_uint)
    if lower.contains("approve") || lower.contains("0x095ea7b3") {
        if lower.contains("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") || lower.contains("max") {
            risk_score += 75;
            threats.push("High Risk: Unlimited token approval (Max Uint256) requested. Spender can deplete your entire token balance.".to_string());
        }
    }

    // 3. EIP-2612 / Permit2 Gasless Drainer
    if lower.contains("permit") || lower.contains("permit2") || lower.contains("0xd505accf") {
        if lower.contains("allowance") || lower.contains("batch") || lower.contains("signature") {
            risk_score += 90;
            threats.push("Permit2 Gasless Drainer Signature: Off-chain signature will be executed by adverse actor to sweep all wallet tokens.".to_string());
        }
    }

    // 4. Soroban / Stellar Trustline or Auth Delegation Sweeper
    if lower.contains("change_trust") || lower.contains("authorize_entry") || lower.contains("clawback") {
        risk_score += 65;
        threats.push("Soroban/Stellar Sensitive Invariant: Contract requests authorization delegation or trustline manipulation.".to_string());
    }

    // 5. TransferFrom / Sweep Call
    if lower.contains("transferfrom") && (lower.contains("drain") || lower.contains("sweep") || lower.contains("vault")) {
        risk_score += 70;
        threats.push("Suspicious transferFrom execution pattern targeting non-privileged account.".to_string());
    }

    if risk_score > 100 {
        risk_score = 100;
    }

    let is_drainer = risk_score >= 70;

    let (en, hi) = if is_drainer {
        (
            "🚨 CRITICAL WALLET DRAINER DETECTED! DO NOT SIGN! Signing this transaction grants the contract permission to sweep all your tokens or NFTs.".to_string(),
            "🚨 MAHA-KHATRA: YE WALLET DRAINER HAI! SIGN MAT KARNA! Agar sign kiya toh aapke wallet ke saare crypto tokens aur NFTs 1 second me chori ho jayenge.".to_string(),
        )
    } else if risk_score > 30 {
        (
            "⚠️ CAUTION: Transaction requests elevated permissions. Verify spender address before signing.".to_string(),
            "⚠️ SAVDHAAN: Ye transaction badi permissions maang rahi hai. Spender ka address dhyan se check karein.".to_string(),
        )
    } else {
        (
            "✅ Transaction calldata appears standard with normal permissions.".to_string(),
            "✅ Transaction safe aur standard lag rahi hai.".to_string(),
        )
    };

    ContractAuditResult {
        target: calldata_or_method.to_string(),
        risk_score,
        is_drainer,
        threats,
        human_verdict_en: en,
        human_verdict_hi: hi,
    }
}
