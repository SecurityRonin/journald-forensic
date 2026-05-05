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
        // realtime_us is microseconds since epoch; max sane value fits i64
        #[allow(clippy::cast_possible_wrap)]
        let secs = (self.realtime_us / 1_000_000) as i64;
        // remainder is 0..999_999 µs → 0..999_999_000 ns, always fits u32
        #[allow(clippy::cast_possible_truncation)]
        let nanos = ((self.realtime_us % 1_000_000) * 1_000) as u32;
        Utc.timestamp_opt(secs, nanos)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
    }

    /// Look up a text field by key name. Returns `None` if the key is absent
    /// or if the value is binary.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|f| f.key == key).and_then(|f| {
            if let JournalFieldValue::Text(ref s) = f.value {
                Some(s.as_str())
            } else {
                None
            }
        })
    }

    /// Convenience: return the `MESSAGE` field.
    pub fn message(&self) -> Option<&str> {
        self.field("MESSAGE")
    }

    /// Parse the `PRIORITY` field as a `u8`. Returns `None` if absent or unparseable.
    pub fn priority(&self) -> Option<u8> {
        self.field("PRIORITY")?.parse().ok()
    }

    /// Return the `SYSLOG_IDENTIFIER` field.
    pub fn syslog_identifier(&self) -> Option<&str> {
        self.field("SYSLOG_IDENTIFIER")
    }

    /// Parse the `_PID` field as a `u32`. Returns `None` if absent or unparseable.
    pub fn pid(&self) -> Option<u32> {
        self.field("_PID")?.parse().ok()
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
    ///
    /// Expected format:
    /// `s=<uuid_hex32>;i=<hex>;b=<uuid_hex32>;m=<hex>;t=<hex>;x=<hex>`
    pub fn parse(cursor_str: &str) -> Result<Self, JournalError> {
        let make_err = || JournalError::InvalidCursor {
            cursor: cursor_str.to_string(),
        };

        let mut seqnum_id: Option<[u8; 16]> = None;
        let mut seqnum: Option<u64> = None;
        let mut boot_id: Option<[u8; 16]> = None;
        let mut monotonic_us: Option<u64> = None;
        let mut realtime_us: Option<u64> = None;
        let mut xor_hash: Option<u64> = None;

        for part in cursor_str.split(';') {
            let (key, val) = part.split_once('=').ok_or_else(make_err)?;
            match key {
                "s" => seqnum_id = Some(parse_uuid_hex(val).ok_or_else(make_err)?),
                "i" => seqnum = Some(u64::from_str_radix(val, 16).map_err(|_| make_err())?),
                "b" => boot_id = Some(parse_uuid_hex(val).ok_or_else(make_err)?),
                "m" => monotonic_us = Some(u64::from_str_radix(val, 16).map_err(|_| make_err())?),
                "t" => realtime_us = Some(u64::from_str_radix(val, 16).map_err(|_| make_err())?),
                "x" => xor_hash = Some(u64::from_str_radix(val, 16).map_err(|_| make_err())?),
                _ => return Err(make_err()),
            }
        }

        Ok(JournalCursor {
            seqnum_id: seqnum_id.ok_or_else(make_err)?,
            seqnum: seqnum.ok_or_else(make_err)?,
            boot_id: boot_id.ok_or_else(make_err)?,
            monotonic_us: monotonic_us.ok_or_else(make_err)?,
            realtime_us: realtime_us.ok_or_else(make_err)?,
            xor_hash: xor_hash.ok_or_else(make_err)?,
        })
    }

    /// Serialize back to the canonical cursor string format.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!(
            "s={};i={:x};b={};m={:x};t={:x};x={:x}",
            uuid_to_hex(&self.seqnum_id),
            self.seqnum,
            uuid_to_hex(&self.boot_id),
            self.monotonic_us,
            self.realtime_us,
            self.xor_hash,
        )
    }
}

/// Parse a 32-char hex string (no dashes) into a 16-byte UUID array.
fn parse_uuid_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn uuid_to_hex(bytes: &[u8; 16]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
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
