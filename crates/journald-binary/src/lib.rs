//! Binary format parser for systemd journal files.
//!
//! All functions accept `&[u8]` slices — no file I/O.

use journald_core::JournalError;

/// The 8-byte file magic at offset 0 of the journal file header object.
pub const JOURNAL_MAGIC: &[u8; 8] = b"LPKSHHRH";

/// Journal file state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JournalState {
    Offline,
    Online,
    Archived,
}

/// Parsed journal file header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JournalHeader {
    pub compatible_flags: u32,
    pub incompatible_flags: u32,
    pub state: JournalState,
    pub machine_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub seqnum_id: [u8; 16],
    pub n_objects: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub head_entry_realtime: u64,
    pub tail_entry_realtime: u64,
}

/// All known object types in a journal file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JournalObjectType {
    Unused,
    Data,
    Field,
    Entry,
    DataHashTable,
    FieldHashTable,
    EntryArray,
    Tag,
}

/// Parsed object header (8 bytes + size field = 16 bytes total as laid out in the spec).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectHeader {
    pub object_type: JournalObjectType,
    pub flags: u8,
    pub size: u64,
}

/// Verify that `buf` begins with the journal magic bytes.
pub fn parse_journal_magic(buf: &[u8]) -> Result<(), JournalError> {
    todo!()
}

/// Parse the journal file header from `buf`.
pub fn parse_header(buf: &[u8]) -> Result<JournalHeader, JournalError> {
    todo!()
}

/// Parse an object header from `buf` (must be at least 16 bytes).
///
/// Layout (little-endian):
/// - offset 0: type u8
/// - offset 1: flags u8
/// - offset 2..7: reserved [u8; 6]
/// - offset 8..15: size u64
pub fn parse_object_header(buf: &[u8]) -> Result<ObjectHeader, JournalError> {
    todo!()
}

/// Map a raw object type byte to `JournalObjectType`.
pub fn object_type_from_byte(b: u8) -> Result<JournalObjectType, JournalError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_are_correct() {
        assert_eq!(JOURNAL_MAGIC, b"LPKSHHRH");
    }

    #[test]
    fn parse_magic_accepts_valid_header() {
        let mut buf = vec![0u8; 256];
        buf[..8].copy_from_slice(b"LPKSHHRH");
        assert!(parse_journal_magic(&buf).is_ok());
    }

    #[test]
    fn parse_magic_rejects_invalid() {
        let buf = b"NOTAFILE".to_vec();
        assert!(parse_journal_magic(&buf).is_err());
    }

    #[test]
    fn parse_magic_empty_buffer_returns_err() {
        assert!(parse_journal_magic(&[]).is_err());
    }

    #[test]
    fn object_type_from_byte_all_known_types() {
        assert!(matches!(object_type_from_byte(0), Ok(JournalObjectType::Unused)));
        assert!(matches!(object_type_from_byte(1), Ok(JournalObjectType::Data)));
        assert!(matches!(object_type_from_byte(2), Ok(JournalObjectType::Field)));
        assert!(matches!(object_type_from_byte(3), Ok(JournalObjectType::Entry)));
        assert!(matches!(object_type_from_byte(4), Ok(JournalObjectType::DataHashTable)));
        assert!(matches!(object_type_from_byte(5), Ok(JournalObjectType::FieldHashTable)));
        assert!(matches!(object_type_from_byte(6), Ok(JournalObjectType::EntryArray)));
        assert!(matches!(object_type_from_byte(7), Ok(JournalObjectType::Tag)));
    }

    #[test]
    fn object_type_from_byte_unknown_returns_err() {
        assert!(object_type_from_byte(99).is_err());
    }

    #[test]
    fn parse_object_header_reads_type_flags_size() {
        // ObjectHeader layout: type(1), flags(1), reserved(6), size(8) — little-endian
        let mut buf = [0u8; 16];
        buf[0] = 3; // Entry type
        buf[1] = 0; // flags = no compression
        // bytes 2-7: reserved (zero)
        // bytes 8-15: size = 128 as little-endian u64
        buf[8..16].copy_from_slice(&128u64.to_le_bytes());
        let hdr = parse_object_header(&buf).unwrap();
        assert!(matches!(hdr.object_type, JournalObjectType::Entry));
        assert_eq!(hdr.size, 128);
        assert_eq!(hdr.flags, 0);
    }

    #[test]
    fn parse_object_header_too_short_returns_err() {
        let buf = [0u8; 8];
        assert!(parse_object_header(&buf).is_err());
    }
}
