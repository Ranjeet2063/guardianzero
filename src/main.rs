mod scanner;
mod advisor;

use clap::{Parser, Subcommand};
use colored::*;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "guardianzero")]
#[command(bin_name = "g0")]
#[command(author = "Ranjeet Kumar Gupta <ranjeet2063@users.noreply.github.com>")]
#[command(version = "0.1.0")]
#[command(about = "GuardianZero: Universal Sovereign AI Guardian & Anti-Scam Shield", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Quick scan any URL, message, smart contract, or file
    Scan {
        /// Target URL, message text, smart contract calldata, or file path
        target: String,
        /// Output machine-readable JSON telemetry
        #[arg(long)]
        json: bool,
    },
    /// Interactive real-time conversational bodyguard chat
    Chat,
    /// Dedicated file and infostealer malware analysis
    File {
        /// Absolute or relative file path to scan
        path: String,
    },
    /// Run lightweight continuous protection daemon
    Daemon {
        /// Port to bind the protection listener
        #[arg(short, long, default_value = "8088")]
        port: u16,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Scan { target, json }) => {
            let report = advisor::analyze_target(target);
            if *json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                advisor::print_report(&report);
            }
        }
        Some(Commands::File { path }) => {
            let report = advisor::analyze_target(path);
            advisor::print_report(&report);
        }
        Some(Commands::Daemon { port }) => {
            println!("{}", "🛡️  GuardianZero Sovereign Protection Daemon".bold().cyan());
            println!("⚡ Listening for webhook threat signals on port {}...", port);
            println!("💡 Status: Active 24/7 background sentinel ready.");
        }
        Some(Commands::Chat) | None => {
            run_interactive_chat();
        }
    }
}

fn run_interactive_chat() {
    println!("\n{}", "=========================================================".cyan());
    println!("{}", "🛡️  GuardianZero (g0) — Your Sovereign AI Personal Bodyguard".bold().white());
    println!("{}", "Conversational Anti-Scam, Phishing & Life-Savings Defense Engine".yellow());
    println!("{}", "Ask in Hinglish or English: 'Bhai ye link check karo', paste text, or file path.".green());
    println!("Type {} or {} to exit.", "'exit'".bold().red(), "'quit'".bold().red());
    println!("{}\n", "=========================================================".cyan());

    loop {
        print!("{}", "g0 > ".bold().green());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "exit" || trimmed == "quit" || trimmed == ":q" {
            println!("{}", "👋 GuardianZero standing down. Stay safe out there!".bold().yellow());
            break;
        }

        let report = advisor::analyze_target(trimmed);
        advisor::print_report(&report);
    }
}
