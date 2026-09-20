//! `jd` — systemd journal forensic analysis CLI.
//!
//! Subcommands:
//! - `jd timeline <path>`              — emit chronological entry timeline (JSONL)
//! - `jd fields <path>`               — list all field names found in the journal
//! - `jd search <path> <FIELD=VALUE>` — filter entries by field match
//!
//! Exit codes:
//! - `0` = success
//! - `1` = bad magic / parse error / not found

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use journald_binary::{parse_entries, parse_journal_magic};
use journald_core::{JournalEntry, JournalFieldValue};
use std::io::Read;
use std::path::PathBuf;

/// `jd` — systemd journal forensic analysis tool.
///
/// Parses binary `.journal` files for forensic examination: timeline extraction,
/// field enumeration, and entry search.
#[derive(Parser)]
#[command(
    name = "jd4n6",
    about = "systemd journal forensic analysis tool",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Emit a chronological timeline of journal entries as JSONL.
    ///
    /// Each line is a JSON object with `seqnum`, `realtime_us`, and field key=value pairs.
    Timeline {
        /// Path to the `.journal` file.
        path: PathBuf,
    },
    /// List all unique field names found across all entries in the journal.
    Fields {
        /// Path to the `.journal` file.
        path: PathBuf,
    },
    /// Search journal entries where a field matches a given value.
    ///
    /// The filter must be in `FIELD=VALUE` format (e.g. `PRIORITY=3`).
    Search {
        /// Path to the `.journal` file.
        path: PathBuf,
        /// Field filter in `FIELD=VALUE` format.
        filter: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Timeline { path } => cmd_timeline(&path),
        Cmd::Fields { path } => cmd_fields(&path),
        Cmd::Search { path, filter } => cmd_search(&path, &filter),
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

/// Read a journal file and validate its magic. Returns raw bytes.
fn read_and_validate(path: &PathBuf) -> Result<Vec<u8>> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("cannot open '{}'", path.display()))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .with_context(|| format!("cannot read '{}'", path.display()))?;
    parse_journal_magic(&data)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("'{}' is not a valid journal file", path.display()))?;
    Ok(data)
}

/// Render a decoded [`JournalEntry`] as a flat JSON object (seqnum, timestamps,
/// then each field as `key: "value"`).
fn entry_to_json(entry: &JournalEntry) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "seqnum".to_string(),
        serde_json::Value::Number(entry.seqnum.into()),
    );
    obj.insert(
        "realtime_us".to_string(),
        serde_json::Value::Number(entry.realtime_us.into()),
    );
    obj.insert(
        "monotonic_us".to_string(),
        serde_json::Value::Number(entry.monotonic_us.into()),
    );
    for field in &entry.fields {
        let value_str = match &field.value {
            JournalFieldValue::Text(s) => s.clone(),
            JournalFieldValue::Binary(b) => String::from_utf8_lossy(b).into_owned(),
        };
        obj.insert(field.key.clone(), serde_json::Value::String(value_str));
    }
    serde_json::Value::Object(obj)
}

fn cmd_timeline(path: &PathBuf) -> Result<()> {
    let data = read_and_validate(path)?;
    let entries = parse_entries(&data);
    if entries.is_empty() {
        eprintln!("no entries found in '{}'", path.display());
    }
    for entry in &entries {
        println!("{}", entry_to_json(entry));
    }
    Ok(())
}

fn cmd_fields(path: &PathBuf) -> Result<()> {
    let data = read_and_validate(path)?;
    let entries = parse_entries(&data);
    let mut field_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in &entries {
        for field in &entry.fields {
            field_names.insert(field.key.clone());
        }
    }
    for name in &field_names {
        println!("{name}");
    }
    Ok(())
}

fn cmd_search(path: &PathBuf, filter: &str) -> Result<()> {
    let (filter_key, filter_val) = filter
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("filter must be FIELD=VALUE, got: '{filter}'"))?;
    let data = read_and_validate(path)?;
    let entries = parse_entries(&data);
    let filter_val_bytes = filter_val.as_bytes();
    for entry in &entries {
        let matches = entry.fields.iter().any(|f| {
            f.key == filter_key
                && match &f.value {
                    JournalFieldValue::Text(s) => s.as_bytes() == filter_val_bytes,
                    JournalFieldValue::Binary(b) => b.as_slice() == filter_val_bytes,
                }
        });
        if matches {
            println!("{}", entry_to_json(entry));
        }
    }
    Ok(())
}
