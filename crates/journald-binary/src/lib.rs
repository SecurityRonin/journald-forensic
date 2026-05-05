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
    if buf.len() < 8 {
        return Err(JournalError::BufferTooShort { needed: 8, got: buf.len() });
    }
    let found: [u8; 8] = buf[..8].try_into().unwrap();
    if &found != JOURNAL_MAGIC {
        return Err(JournalError::InvalidMagic { found });
    }
    Ok(())
}

/// Parse the journal file header from `buf`.
///
/// Minimum layout (offsets are from the start of the header object, which
/// begins with the 8-byte magic):
///
/// ```text
///  0..8    signature / magic
///  8..12   compatible_flags (u32 LE)
/// 12..16   incompatible_flags (u32 LE)
/// 16       state (u8)
/// 17..24   reserved (7 bytes)
/// 24..40   file_id [u8; 16]
/// 40..56   machine_id [u8; 16]
/// 56..72   boot_id [u8; 16]
/// 72..88   seqnum_id [u8; 16]
/// 88..96   header_size (u64 LE)
/// 96..104  arena_size (u64 LE)
/// ...
/// (fields below are at higher offsets; read what we need)
/// 160..168  n_objects (u64 LE)
/// 168..176  n_entries (u64 LE)
/// 176..184  tail_entry_seqnum (u64 LE)
/// 184..192  head_entry_seqnum (u64 LE)
/// ...
/// 208..216  head_entry_realtime (u64 LE)
/// 216..224  tail_entry_realtime (u64 LE)
/// ```
pub fn parse_header(buf: &[u8]) -> Result<JournalHeader, JournalError> {
    const MIN_SIZE: usize = 224;
    if buf.len() < MIN_SIZE {
        return Err(JournalError::BufferTooShort { needed: MIN_SIZE, got: buf.len() });
    }
    parse_journal_magic(buf)?;

    let compatible_flags = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let incompatible_flags = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let state = match buf[16] {
        0 => JournalState::Offline,
        2 => JournalState::Archived,
        _ => JournalState::Online, // 1 = Online; treat unknown as Online (suspicious)
    };

    let machine_id: [u8; 16] = buf[40..56].try_into().unwrap();
    let boot_id: [u8; 16] = buf[56..72].try_into().unwrap();
    let seqnum_id: [u8; 16] = buf[72..88].try_into().unwrap();

    let n_objects = u64::from_le_bytes(buf[160..168].try_into().unwrap());
    let n_entries = u64::from_le_bytes(buf[168..176].try_into().unwrap());
    let tail_entry_seqnum = u64::from_le_bytes(buf[176..184].try_into().unwrap());
    let head_entry_seqnum = u64::from_le_bytes(buf[184..192].try_into().unwrap());
    let head_entry_realtime = u64::from_le_bytes(buf[208..216].try_into().unwrap());
    let tail_entry_realtime = u64::from_le_bytes(buf[216..224].try_into().unwrap());

    Ok(JournalHeader {
        compatible_flags,
        incompatible_flags,
        state,
        machine_id,
        boot_id,
        seqnum_id,
        n_objects,
        n_entries,
        tail_entry_seqnum,
        head_entry_seqnum,
        head_entry_realtime,
        tail_entry_realtime,
    })
}

/// Parse an object header from `buf` (must be at least 16 bytes).
///
/// Layout (little-endian):
/// - offset 0: type u8
/// - offset 1: flags u8
/// - offset 2..7: reserved [u8; 6]
/// - offset 8..15: size u64
pub fn parse_object_header(buf: &[u8]) -> Result<ObjectHeader, JournalError> {
    if buf.len() < 16 {
        return Err(JournalError::BufferTooShort { needed: 16, got: buf.len() });
    }
    let object_type = object_type_from_byte(buf[0])?;
    let flags = buf[1];
    let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    Ok(ObjectHeader { object_type, flags, size })
}

/// Map a raw object type byte to `JournalObjectType`.
pub fn object_type_from_byte(b: u8) -> Result<JournalObjectType, JournalError> {
    match b {
        0 => Ok(JournalObjectType::Unused),
        1 => Ok(JournalObjectType::Data),
        2 => Ok(JournalObjectType::Field),
        3 => Ok(JournalObjectType::Entry),
        4 => Ok(JournalObjectType::DataHashTable),
        5 => Ok(JournalObjectType::FieldHashTable),
        6 => Ok(JournalObjectType::EntryArray),
        7 => Ok(JournalObjectType::Tag),
        _ => Err(JournalError::InvalidObjectType { type_byte: b }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- forensicnomicon integration tests (RED: forensicnomicon dep not yet wired) ---

    #[test]
    fn binary_magic_matches_forensicnomicon_constant() {
        use forensicnomicon::journald::{JOURNAL_MAGIC as NOM_MAGIC, object_type, header_offset};
        assert_eq!(NOM_MAGIC, b"LPKSHHRH");
        assert_eq!(object_type::ENTRY, 3);
        assert_eq!(header_offset::BOOT_ID, 56);
    }

    #[test]
    fn parse_magic_uses_forensicnomicon_constant() {
        use forensicnomicon::journald::JOURNAL_MAGIC as NOM_MAGIC;
        let mut buf = vec![0u8; 256];
        buf[..8].copy_from_slice(NOM_MAGIC);
        assert!(parse_journal_magic(&buf).is_ok());
    }

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
