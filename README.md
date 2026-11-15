# 🛡️ GuardianZero (`g0`)

> **Universal Sovereign AI Guardian & Bare-Metal Anti-Scam, Phishing and Drainer Defense Engine in Rust.**

[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Tests: 100% Green](https://img.shields.io/badge/tests-100%25%20passing-brightgreen.svg)]()

Every year, over **$10 Billion USD** is stolen from developers, crypto users, and everyday individuals through deceptive phishing domains, Web3 wallet drainers, fake freelance client malware, and social engineering scams.

**GuardianZero (`g0`)** is an unprivileged, microsecond-fast sovereign security engine and conversational AI bodyguard. It analyzes incoming links, files, smart contract approvals, and messages, translating complex threat telemetry into **crystal-clear, zero-jargon human advice in Hinglish and English**.

---

## ⚡ Key Highlights

- **Omnipresent Threat Scanning**: Real-time detection across 4 critical attack vectors:
  1. **Deceptive URLs**: Catches Punycode spoofing, typosquatting, high-risk TLDs (`.xyz`, `.top`), and airdrop drainer paths.
  2. **Smart Contract Drainers**: Detects `setApprovalForAll`, unlimited `permit2` signatures, and bytecode token sweepers.
  3. **Infostealer Malware**: Scans binaries/scripts for Chrome saved password theft (`Login Data`), crypto keystore harvesting (MetaMask, Phantom), and Telegram `tdata` hijacking.
  4. **Social Engineering**: Identifies Ponzi doubling tricks, fake job recruiter malware bait, and panic urgency triggers.
- **Deep TraceZero Sandbox Integration**: Untrusted scripts can be executed inside an unprivileged sub-millisecond hardware CoW sandbox (`TraceZero`) without exposing host secrets.
- **Bilingual Conversational Output**: Instant dual Hinglish & English binary safety verdicts with actionable advice.
- **100% User-Space & Daemon-Free**: Zero root / SUID required.

---

## 🚀 Quick Start

### Installation
```bash
# Build from source
cargo install --path /data/guardianzero

# Or run directly via global alias
g0 --version
```

### 1. Interactive Conversational Chat Bodyguard
Run the interactive bodyguard loop to ask about suspicious messages or links:
```bash
$ g0 chat
g0 > Bhai ye link airdrop ka aaya hai: https://metamask-claim-bonus.xyz
```

### 2. Direct CLI Scanner
```bash
# Scan a suspicious URL
g0 scan "https://metamask-verify.xyz/airdrop"

# Scan a smart contract call for drainer signatures
g0 scan "setApprovalForAll(0x1234567890123456789012345678901234567890, true)"

# Scan a file for infostealer malware
g0 file /path/to/suspicious_script.py

# Machine-readable JSON output for integrations
g0 scan "https://binance-airdrop.top" --json
```

---

## 📊 Sample Output

```text
=========================================================
🛡️  GuardianZero (g0) Sovereign Threat Assessment
=========================================================
🔍 Category: URL
📊 Risk Level: CRITICAL (Score: 100/100)

⚠️  Detected Risk Indicators:
   [-] High-risk TLD ('.xyz') commonly used for transient throwaway phishing
   [-] Brand impersonation targeting 'metamask' via domain pattern 'metamask-verify'
   [-] High-risk scam/phishing trigger keyword 'airdrop'

💡 Human Verdict (Hinglish):
   KHATRA! Domain 'metamask-verify.xyz' ek nakli phishing link hai jo aapke crypto keys ya paise churane ke liye banayi gayi hai. Is par click bilkul na karein!

💡 Human Verdict (English):
   CRITICAL PHISHING RISK: Domain 'metamask-verify.xyz' exhibits deceptive impersonation patterns intended to drain credentials or crypto keys.

🛑 Recommended Immediate Action:
   👉 BLOCK & DO NOT CLICK: Close the tab immediately. Never connect crypto wallets or enter passwords.
=========================================================
```

---

## 🧪 Testing

```bash
cargo test
# running 5 tests
# test test_contract_drainer_detection ... ok
# test test_phishing_url_detection ... ok
# test test_infostealer_file_signatures ... ok
# test test_social_engineering_scam_detection ... ok
# test test_safe_url_detection ... ok
```

---

## 👤 Author & Architecture

- **Architect**: Ranjeet Kumar Gupta ([@Ranjeet2063](https://github.com/Ranjeet2063))
- **License**: MIT OR Apache-2.0
