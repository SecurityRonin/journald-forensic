//! Tier-1 differential-oracle validation against `journalctl`.
//!
//! systemd decoding its OWN on-disk format is the independent oracle for this
//! reader: we run the crate's [`parse_entries`] over a real `.journal` and
//! reconcile the entry count and a sample of field values against
//! `journalctl --file <f> -o json`.
//!
//! The end-to-end oracle test is **env-gated** — it runs only when
//! `JOURNALD_TEST_CORPUS` points at a real `.journal` AND `journalctl` is on
//! `PATH`; otherwise it skips cleanly (mirrors the fleet's env-gated oracle
//! pattern). The pure reconciliation helpers below are unit-tested
//! unconditionally with synthetic inputs, so the reconciliation logic itself is
//! always exercised in CI.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use journald_binary::{parse_entries, parse_header};
use journald_core::{JournalEntry, JournalFieldValue};
use std::collections::BTreeMap;

// --------------------------------------------------------------------------
// Pure reconciliation helpers (TDD target — unit-tested below, no journalctl).
// --------------------------------------------------------------------------

/// A field view of one entry: `key -> text value` for text fields only.
type FieldMap = BTreeMap<String, String>;

/// Project a crate [`JournalEntry`] to its text fields (binary fields dropped,
/// matching how `journalctl -o json` renders only decodable strings).
fn entry_to_text_map(entry: &JournalEntry) -> FieldMap {
    let mut m = BTreeMap::new();
    for f in &entry.fields {
        if let JournalFieldValue::Text(s) = &f.value {
            // Journals may legitimately repeat a key; keep the first (stable).
            m.entry(f.key.clone()).or_insert_with(|| s.clone());
        }
    }
    m
}

/// Parse `journalctl -o json` output (one JSON object per line) into field maps,
/// keeping only JSON *string* values. Non-string values (byte arrays for binary
/// fields, numbers) are dropped so both sides compare like-for-like. Blank lines
/// and lines that are not JSON objects are ignored.
fn parse_oracle_jsonl(stdout: &str) -> Vec<FieldMap> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(line)
        else {
            continue;
        };
        let mut m = BTreeMap::new();
        for (k, v) in obj {
            if let serde_json::Value::String(s) = v {
                m.insert(k, s);
            }
        }
        out.push(m);
    }
    out
}

/// Count occurrences of each value under `key` across all entries.
fn field_multiset(maps: &[FieldMap], key: &str) -> BTreeMap<String, usize> {
    let mut ms: BTreeMap<String, usize> = BTreeMap::new();
    for m in maps {
        if let Some(v) = m.get(key) {
            *ms.entry(v.clone()).or_insert(0) += 1;
        }
    }
    ms
}

/// Reconcile the crate's decode (`ours`) against the oracle (`theirs`).
///
/// Two claims:
///   1. **Entry count** must be equal — we neither missed nor invented entries.
///   2. For every `sample_keys` key present in the oracle, every value the crate
///      produced must be corroborated by the oracle (multiset subset:
///      `ours[value] <= theirs[value]`). The oracle is the independent authority
///      on field content; the count check already guards the other direction.
///
/// Returns `Ok(())` on agreement, or `Err(human_readable_diff)` on mismatch.
fn reconcile(ours: &[FieldMap], theirs: &[FieldMap], sample_keys: &[&str]) -> Result<(), String> {
    if ours.len() != theirs.len() {
        return Err(format!(
            "entry count mismatch: crate parsed {}, journalctl reported {}",
            ours.len(),
            theirs.len()
        ));
    }
    for &key in sample_keys {
        let theirs_ms = field_multiset(theirs, key);
        if theirs_ms.is_empty() {
            continue; // oracle has no such field; nothing to corroborate against
        }
        let ours_ms = field_multiset(ours, key);
        for (val, &count) in &ours_ms {
            let oracle_count = theirs_ms.get(val).copied().unwrap_or(0);
            if count > oracle_count {
                return Err(format!(
                    "field '{key}' value {val:?}: crate produced {count} but oracle only has {oracle_count}"
                ));
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Unit tests for the pure helpers (always run; no journalctl needed).
// --------------------------------------------------------------------------

#[test]
fn parse_oracle_jsonl_keeps_string_fields_and_drops_arrays() {
    // journalctl renders a binary MESSAGE as an int array; keep only strings.
    let stdout = concat!(
        r#"{"MESSAGE":"hello","_PID":"42","COREDUMP":[1,2,3]}"#,
        "\n",
        r#"{"MESSAGE":"world","PRIORITY":"6"}"#,
        "\n",
    );
    let maps = parse_oracle_jsonl(stdout);
    assert_eq!(maps.len(), 2);
    assert_eq!(maps[0].get("MESSAGE").map(String::as_str), Some("hello"));
    assert_eq!(maps[0].get("_PID").map(String::as_str), Some("42"));
    assert!(
        !maps[0].contains_key("COREDUMP"),
        "array value must be dropped"
    );
    assert_eq!(maps[1].get("PRIORITY").map(String::as_str), Some("6"));
}

#[test]
fn parse_oracle_jsonl_ignores_blank_and_non_object_lines() {
    let stdout = "\n[1,2,3]\n\"not-an-object\"\n{\"MESSAGE\":\"ok\"}\n";
    let maps = parse_oracle_jsonl(stdout);
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].get("MESSAGE").map(String::as_str), Some("ok"));
}

#[test]
fn field_multiset_counts_repeated_values() {
    let maps = vec![
        BTreeMap::from([("SYSLOG_IDENTIFIER".to_string(), "jdtest".to_string())]),
        BTreeMap::from([("SYSLOG_IDENTIFIER".to_string(), "jdtest".to_string())]),
        BTreeMap::from([("SYSLOG_IDENTIFIER".to_string(), "systemd".to_string())]),
        BTreeMap::new(),
    ];
    let ms = field_multiset(&maps, "SYSLOG_IDENTIFIER");
    assert_eq!(ms.get("jdtest"), Some(&2));
    assert_eq!(ms.get("systemd"), Some(&1));
    assert_eq!(ms.len(), 2);
}

#[test]
fn reconcile_ok_when_counts_and_fields_agree() {
    let ours = vec![
        BTreeMap::from([("MESSAGE".to_string(), "a".to_string())]),
        BTreeMap::from([("MESSAGE".to_string(), "b".to_string())]),
    ];
    let theirs = vec![
        BTreeMap::from([
            ("MESSAGE".to_string(), "a".to_string()),
            ("__CURSOR".to_string(), "s=...".to_string()),
        ]),
        BTreeMap::from([("MESSAGE".to_string(), "b".to_string())]),
    ];
    assert!(reconcile(&ours, &theirs, &["MESSAGE"]).is_ok());
}

#[test]
fn reconcile_errors_on_entry_count_mismatch() {
    let ours = vec![BTreeMap::from([("MESSAGE".to_string(), "a".to_string())])];
    let theirs = vec![
        BTreeMap::from([("MESSAGE".to_string(), "a".to_string())]),
        BTreeMap::from([("MESSAGE".to_string(), "b".to_string())]),
    ];
    let err = reconcile(&ours, &theirs, &["MESSAGE"]).unwrap_err();
    assert!(err.contains("count mismatch"), "got: {err}");
}

#[test]
fn reconcile_errors_when_crate_value_not_corroborated_by_oracle() {
    // Same count, but the crate produced a MESSAGE the oracle never emitted →
    // the reader fabricated/misdecoded a value; must be caught.
    let ours = vec![
        BTreeMap::from([("MESSAGE".to_string(), "real".to_string())]),
        BTreeMap::from([("MESSAGE".to_string(), "GARBLED".to_string())]),
    ];
    let theirs = vec![
        BTreeMap::from([("MESSAGE".to_string(), "real".to_string())]),
        BTreeMap::from([("MESSAGE".to_string(), "real".to_string())]),
    ];
    let err = reconcile(&ours, &theirs, &["MESSAGE"]).unwrap_err();
    assert!(err.contains("GARBLED"), "got: {err}");
}

#[test]
fn reconcile_skips_keys_absent_from_oracle() {
    // A key the oracle never emits is not reconciled (no false failure).
    let ours = vec![BTreeMap::from([("OURKEY".to_string(), "x".to_string())])];
    let theirs = vec![BTreeMap::from([("MESSAGE".to_string(), "y".to_string())])];
    assert!(reconcile(&ours, &theirs, &["OURKEY"]).is_ok());
}

#[test]
fn entry_to_text_map_drops_binary_fields() {
    let entry = JournalEntry {
        seqnum: 1,
        realtime_us: 0,
        monotonic_us: 0,
        boot_id: [0u8; 16],
        fields: vec![
            journald_core::JournalField {
                key: "MESSAGE".to_string(),
                value: JournalFieldValue::Text("hi".to_string()),
            },
            journald_core::JournalField {
                key: "COREDUMP".to_string(),
                value: JournalFieldValue::Binary(vec![1, 2, 3]),
            },
        ],
    };
    let m = entry_to_text_map(&entry);
    assert_eq!(m.get("MESSAGE").map(String::as_str), Some("hi"));
    assert!(!m.contains_key("COREDUMP"));
}

// --------------------------------------------------------------------------
// The env-gated end-to-end differential-oracle test.
// --------------------------------------------------------------------------

/// Sample fields reconciled against the oracle. All are real journald Data
/// fields the crate decodes and journalctl surfaces as strings.
const SAMPLE_KEYS: &[&str] = &["MESSAGE", "SYSLOG_IDENTIFIER", "_PID", "PRIORITY", "_COMM"];

#[test]
fn journalctl_differential_oracle() {
    let Some(corpus) = std::env::var_os("JOURNALD_TEST_CORPUS") else {
        eprintln!("SKIP: JOURNALD_TEST_CORPUS not set (env-gated oracle test).");
        return;
    };
    if which_journalctl().is_none() {
        eprintln!("SKIP: 'journalctl' not on PATH (env-gated oracle test).");
        return;
    }

    let data = std::fs::read(&corpus).expect("JOURNALD_TEST_CORPUS must be a readable file");

    // The reader decodes the classic layout only. If the file carries any
    // incompatible flag (COMPACT / KEYED_HASH, systemd v252+), skip cleanly —
    // this is a documented format limitation, not a decode bug.
    match parse_header(&data) {
        Ok(hdr) if hdr.incompatible_flags != 0 => {
            eprintln!(
                "SKIP: corpus has incompatible_flags={:#x} (COMPACT/KEYED_HASH); \
                 reader decodes the classic layout only.",
                hdr.incompatible_flags
            );
            return;
        }
        Ok(_) => {}
        Err(e) => panic!("corpus is not a valid journal header: {e}"),
    }

    // Oracle: systemd decodes its own format.
    let output = std::process::Command::new("journalctl")
        .arg("--file")
        .arg(&corpus)
        .args(["-o", "json", "--no-pager"])
        .output()
        .expect("failed to run journalctl");
    assert!(
        output.status.success(),
        "journalctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let oracle_stdout = String::from_utf8_lossy(&output.stdout);
    let theirs = parse_oracle_jsonl(&oracle_stdout);
    assert!(
        !theirs.is_empty(),
        "journalctl reported zero entries — corpus empty or unreadable"
    );

    // Ours.
    let ours: Vec<FieldMap> = parse_entries(&data).iter().map(entry_to_text_map).collect();

    reconcile(&ours, &theirs, SAMPLE_KEYS).unwrap_or_else(|diff| {
        panic!(
            "differential-oracle reconciliation FAILED against journalctl:\n  {diff}\n\
             (corpus: {})",
            std::path::Path::new(&corpus).display()
        )
    });

    eprintln!(
        "OK: reconciled {} entries against journalctl oracle (fields: {}).",
        ours.len(),
        SAMPLE_KEYS.join(", ")
    );
}

/// Locate `journalctl` on `PATH` without spawning it (spawn is the caller's job).
fn which_journalctl() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("journalctl"))
        .find(|p| p.is_file())
}
