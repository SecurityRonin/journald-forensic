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
use journald_binary::{parse_journal_magic, parse_object_header, JournalObjectType};
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

/// Parsed entry from the journal arena walk.
type EntryRecord = (u64, u64, u64, Vec<(String, Vec<u8>)>);

/// Very lightweight entry scanner: walk objects sequentially looking for Entry objects.
/// Returns a list of `(seqnum, realtime_us, monotonic_us, fields)`.
///
/// This is a best-effort implementation for the CLI — it does not follow hash table
/// chains, but walks the arena sequentially from after the header.
#[allow(clippy::cast_possible_truncation)]
fn scan_entries(data: &[u8]) -> Vec<EntryRecord> {
    // The journal header is at offset 0; header_size is at offset 88..96 (LE u64).
    const MIN_HEADER: usize = 96;
    if data.len() < MIN_HEADER {
        return Vec::new();
    }
    let raw_header_size = u64::from_le_bytes(data[88..96].try_into().unwrap_or([0; 8])) as usize;
    let arena_start = raw_header_size.max(240);
    if arena_start >= data.len() {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut pos = arena_start;

    while pos + 16 <= data.len() {
        let buf = &data[pos..];
        let Ok(obj) = parse_object_header(buf) else {
            pos += 8;
            continue;
        };
        let size = obj.size as usize;
        if size < 16 {
            pos += 8;
            continue;
        }

        if obj.object_type == JournalObjectType::Entry {
            // Entry object layout (after the 16-byte object header):
            //   +16  seqnum   u64
            //   +24  realtime u64
            //   +32  monotonic u64
            //   +40  boot_id  [u8; 16]
            //   +56  xor_hash u64
            //   +64  items[]  (offset u64, hash u64) * N
            if pos + 64 > data.len() {
                pos += size.max(8);
                continue;
            }
            let seqnum = u64::from_le_bytes(data[pos + 16..pos + 24].try_into().unwrap_or([0; 8]));
            let realtime =
                u64::from_le_bytes(data[pos + 24..pos + 32].try_into().unwrap_or([0; 8]));
            let monotonic =
                u64::from_le_bytes(data[pos + 32..pos + 40].try_into().unwrap_or([0; 8]));

            let items_start = pos + 64;
            let obj_end = (pos + size).min(data.len());
            let mut fields = Vec::new();

            let mut item_pos = items_start;
            while item_pos + 16 <= obj_end {
                let data_offset =
                    u64::from_le_bytes(data[item_pos..item_pos + 8].try_into().unwrap_or([0; 8]))
                        as usize;
                item_pos += 16;

                if data_offset + 16 > data.len() {
                    continue;
                }
                let Ok(data_obj) = parse_object_header(&data[data_offset..]) else {
                    continue;
                };
                if data_obj.object_type != JournalObjectType::Data {
                    continue;
                }
                // Data object payload starts at +64 within the Data object
                let payload_start = data_offset + 64;
                let payload_end = (data_offset + data_obj.size as usize).min(data.len());
                if payload_start >= payload_end {
                    continue;
                }
                let payload = &data[payload_start..payload_end];
                // payload is "KEY=value" in bytes
                if let Some(eq_pos) = payload.iter().position(|&b| b == b'=') {
                    let key = String::from_utf8_lossy(&payload[..eq_pos]).into_owned();
                    let value = payload[eq_pos + 1..].to_vec();
                    fields.push((key, value));
                }
            }
            entries.push((seqnum, realtime, monotonic, fields));
        }

        pos += size.max(8);
    }
    entries
}

fn cmd_timeline(path: &PathBuf) -> Result<()> {
    let data = read_and_validate(path)?;
    let entries = scan_entries(&data);
    if entries.is_empty() {
        eprintln!("no entries found in '{}'", path.display());
    }
    for (seqnum, realtime_us, monotonic_us, fields) in &entries {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "seqnum".to_string(),
            serde_json::Value::Number((*seqnum).into()),
        );
        obj.insert(
            "realtime_us".to_string(),
            serde_json::Value::Number((*realtime_us).into()),
        );
        obj.insert(
            "monotonic_us".to_string(),
            serde_json::Value::Number((*monotonic_us).into()),
        );
        for (key, val) in fields {
            let value_str = String::from_utf8_lossy(val).into_owned();
            obj.insert(key.clone(), serde_json::Value::String(value_str));
        }
        println!("{}", serde_json::Value::Object(obj));
    }
    Ok(())
}

fn cmd_fields(path: &PathBuf) -> Result<()> {
    let data = read_and_validate(path)?;
    let entries = scan_entries(&data);
    let mut field_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, _, _, fields) in &entries {
        for (key, _) in fields {
            field_names.insert(key.clone());
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
    let entries = scan_entries(&data);
    let filter_val_bytes = filter_val.as_bytes();
    for (seqnum, realtime_us, monotonic_us, fields) in &entries {
        let matches = fields
            .iter()
            .any(|(k, v)| k == filter_key && v.as_slice() == filter_val_bytes);
        if matches {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "seqnum".to_string(),
                serde_json::Value::Number((*seqnum).into()),
            );
            obj.insert(
                "realtime_us".to_string(),
                serde_json::Value::Number((*realtime_us).into()),
            );
            obj.insert(
                "monotonic_us".to_string(),
                serde_json::Value::Number((*monotonic_us).into()),
            );
            for (key, val) in fields {
                let value_str = String::from_utf8_lossy(val).into_owned();
                obj.insert(key.clone(), serde_json::Value::String(value_str));
            }
            println!("{}", serde_json::Value::Object(obj));
        }
    }
    Ok(())
}
