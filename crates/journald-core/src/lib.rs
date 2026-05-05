//! Core domain types for systemd journal forensic analysis.

use chrono::{DateTime, TimeZone, Utc};
use std::fmt;
use thiserror::Error;

/// A single key=value pair from a journal entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JournalField {
    pub key: String,
    pub value: JournalFieldValue,
}

/// The value of a journal field — either valid UTF-8 text or raw binary bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum JournalFieldValue {
    Text(String),
    Binary(Vec<u8>),
}

/// A single parsed journal entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JournalEntry {
    pub seqnum: u64,
    pub realtime_us: u64,
    pub monotonic_us: u64,
    pub boot_id: [u8; 16],
    pub fields: Vec<JournalField>,
}

impl JournalEntry {
    /// Convert `realtime_us` (microseconds since Unix epoch) to a UTC `DateTime`.
    pub fn realtime_as_datetime(&self) -> DateTime<Utc> {
        todo!()
    }

    /// Look up a text field by key name. Returns `None` if the key is absent
    /// or if the value is binary.
    pub fn field(&self, key: &str) -> Option<&str> {
        todo!()
    }

    /// Convenience: return the `MESSAGE` field.
    pub fn message(&self) -> Option<&str> {
        self.field("MESSAGE")
    }

    /// Parse the `PRIORITY` field as a `u8`. Returns `None` if absent or unparseable.
    pub fn priority(&self) -> Option<u8> {
        todo!()
    }

    /// Return the `SYSLOG_IDENTIFIER` field.
    pub fn syslog_identifier(&self) -> Option<&str> {
        self.field("SYSLOG_IDENTIFIER")
    }

    /// Parse the `_PID` field as a `u32`. Returns `None` if absent or unparseable.
    pub fn pid(&self) -> Option<u32> {
        todo!()
    }
}

/// A parsed journal cursor string.
///
/// Format: `s=<seqnum_id_hex>;i=<seqnum_hex>;b=<boot_id_hex>;m=<monotonic_hex>;t=<realtime_hex>;x=<xor_hash_hex>`
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournalCursor {
    pub seqnum_id: [u8; 16],
    pub seqnum: u64,
    pub boot_id: [u8; 16],
    pub monotonic_us: u64,
    pub realtime_us: u64,
    pub xor_hash: u64,
}

impl JournalCursor {
    /// Parse a journal cursor string into a `JournalCursor`.
    pub fn parse(cursor_str: &str) -> Result<Self, JournalError> {
        todo!()
    }

    /// Serialize back to the canonical cursor string format.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        todo!()
    }
}

/// Errors produced by the journald-forensic library.
#[derive(Debug, Error)]
pub enum JournalError {
    #[error("invalid magic: expected LPKSHHRH, found {found:02x?}")]
    InvalidMagic { found: [u8; 8] },

    #[error("buffer too short: needed {needed} bytes, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("invalid object type byte: {type_byte}")]
    InvalidObjectType { type_byte: u8 },

    #[error("unknown compression flags: {flags}")]
    UnknownCompression { flags: u8 },

    #[error("invalid cursor string: '{cursor}'")]
    InvalidCursor { cursor: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry_with_fields(fields: Vec<(&str, &str)>) -> JournalEntry {
        JournalEntry {
            seqnum: 1,
            realtime_us: 0,
            monotonic_us: 0,
            boot_id: [0u8; 16],
            fields: fields
                .into_iter()
                .map(|(k, v)| JournalField {
                    key: k.to_string(),
                    value: JournalFieldValue::Text(v.to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn entry_field_lookup_by_name() {
        let entry = make_entry_with_fields(vec![("MESSAGE", "hello world"), ("_PID", "42")]);
        assert_eq!(entry.field("MESSAGE"), Some("hello world"));
        assert_eq!(entry.field("_PID"), Some("42"));
        assert_eq!(entry.field("MISSING"), None);
    }

    #[test]
    fn entry_realtime_converts_to_datetime() {
        let entry = JournalEntry {
            seqnum: 1,
            realtime_us: 1_000_000,
            monotonic_us: 0,
            boot_id: [0u8; 16],
            fields: vec![],
        };
        let dt = entry.realtime_as_datetime();
        assert_eq!(dt, Utc.timestamp_opt(1, 0).unwrap());
    }

    #[test]
    fn entry_message_convenience() {
        let entry = make_entry_with_fields(vec![("MESSAGE", "test message")]);
        assert_eq!(entry.message(), Some("test message"));
    }

    #[test]
    fn entry_priority_parses_u8() {
        let entry = make_entry_with_fields(vec![("PRIORITY", "6")]);
        assert_eq!(entry.priority(), Some(6u8));
    }

    #[test]
    fn entry_priority_returns_none_when_absent() {
        let entry = make_entry_with_fields(vec![]);
        assert_eq!(entry.priority(), None);
    }

    #[test]
    fn entry_pid_parses_u32() {
        let entry = make_entry_with_fields(vec![("_PID", "1234")]);
        assert_eq!(entry.pid(), Some(1234u32));
    }

    #[test]
    fn entry_pid_returns_none_when_absent() {
        let entry = make_entry_with_fields(vec![]);
        assert_eq!(entry.pid(), None);
    }

    #[test]
    fn cursor_parse_roundtrip() {
        // All-zero UUIDs, seqnum=1, all others 0
        let cursor_str = "s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=0;t=0;x=0";
        let cursor = JournalCursor::parse(cursor_str).expect("parse should succeed");
        assert_eq!(cursor.seqnum, 1);
        assert_eq!(cursor.seqnum_id, [0u8; 16]);
        assert_eq!(cursor.boot_id, [0u8; 16]);
        assert_eq!(cursor.monotonic_us, 0);
        assert_eq!(cursor.realtime_us, 0);
        assert_eq!(cursor.xor_hash, 0);
        let roundtrip = cursor.to_string();
        assert_eq!(roundtrip, cursor_str);
    }

    #[test]
    fn cursor_parse_invalid_returns_err() {
        let result = JournalCursor::parse("not-a-cursor");
        assert!(result.is_err());
    }

    #[test]
    fn journal_field_value_text_accessible() {
        let val = JournalFieldValue::Text("hello".to_string());
        match val {
            JournalFieldValue::Text(s) => assert_eq!(s, "hello"),
            JournalFieldValue::Binary(_) => panic!("expected Text"),
        }
    }

    #[test]
    fn journal_error_invalid_magic_display() {
        let err = JournalError::InvalidMagic { found: *b"BADMAGIC" };
        let display = format!("{err}");
        assert!(display.contains("LPKSHHRH") || display.contains("invalid magic"));
    }
}
