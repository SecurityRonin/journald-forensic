//! Binary format parser for systemd journal files.
//!
//! All functions accept `&[u8]` slices — no file I/O.

use journald_core::JournalError;

// KNOWLEDGE constants live in forensicnomicon; re-export for downstream crates.
pub use forensicnomicon::journald::JOURNAL_MAGIC;
use forensicnomicon::journald::{header_offset, object_header_offset, object_type as nom_object_type};

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
    if buf.len() < header_offset::MIN_HEADER_SIZE {
        return Err(JournalError::BufferTooShort {
            needed: header_offset::MIN_HEADER_SIZE,
            got: buf.len(),
        });
    }
    parse_journal_magic(buf)?;

    let cf_start = header_offset::COMPATIBLE_FLAGS;
    let compatible_flags = u32::from_le_bytes(buf[cf_start..cf_start + 4].try_into().unwrap());
    let icf_start = header_offset::INCOMPATIBLE_FLAGS;
    let incompatible_flags = u32::from_le_bytes(buf[icf_start..icf_start + 4].try_into().unwrap());
    let state = match buf[header_offset::STATE] {
        0 => JournalState::Offline,
        2 => JournalState::Archived,
        _ => JournalState::Online, // 1 = Online; treat unknown as Online (suspicious)
    };

    let mid = header_offset::MACHINE_ID;
    let machine_id: [u8; 16] = buf[mid..mid + 16].try_into().unwrap();
    let bid = header_offset::BOOT_ID;
    let boot_id: [u8; 16] = buf[bid..bid + 16].try_into().unwrap();
    let sid = header_offset::SEQNUM_ID;
    let seqnum_id: [u8; 16] = buf[sid..sid + 16].try_into().unwrap();

    let off_n_objects = header_offset::N_OBJECTS;
    let n_objects = u64::from_le_bytes(buf[off_n_objects..off_n_objects + 8].try_into().unwrap());
    let off_n_entries = header_offset::N_ENTRIES;
    let n_entries = u64::from_le_bytes(buf[off_n_entries..off_n_entries + 8].try_into().unwrap());
    let off_tail_seqnum = header_offset::TAIL_ENTRY_SEQNUM;
    let tail_entry_seqnum = u64::from_le_bytes(buf[off_tail_seqnum..off_tail_seqnum + 8].try_into().unwrap());
    let off_head_seqnum = header_offset::HEAD_ENTRY_SEQNUM;
    let head_entry_seqnum = u64::from_le_bytes(buf[off_head_seqnum..off_head_seqnum + 8].try_into().unwrap());
    let off_head_rt = header_offset::HEAD_ENTRY_REALTIME;
    let head_entry_realtime = u64::from_le_bytes(buf[off_head_rt..off_head_rt + 8].try_into().unwrap());
    let off_tail_rt = header_offset::TAIL_ENTRY_REALTIME;
    let tail_entry_realtime = u64::from_le_bytes(buf[off_tail_rt..off_tail_rt + 8].try_into().unwrap());

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
    if buf.len() < object_header_offset::HEADER_SIZE {
        return Err(JournalError::BufferTooShort {
            needed: object_header_offset::HEADER_SIZE,
            got: buf.len(),
        });
    }
    let object_type = object_type_from_byte(buf[object_header_offset::TYPE])?;
    let flags = buf[object_header_offset::FLAGS];
    let sz = object_header_offset::SIZE;
    let size = u64::from_le_bytes(buf[sz..sz + 8].try_into().unwrap());
    Ok(ObjectHeader { object_type, flags, size })
}

/// Map a raw object type byte to `JournalObjectType`.
pub fn object_type_from_byte(b: u8) -> Result<JournalObjectType, JournalError> {
    match b {
        v if v == nom_object_type::UNUSED => Ok(JournalObjectType::Unused),
        v if v == nom_object_type::DATA => Ok(JournalObjectType::Data),
        v if v == nom_object_type::FIELD => Ok(JournalObjectType::Field),
        v if v == nom_object_type::ENTRY => Ok(JournalObjectType::Entry),
        v if v == nom_object_type::DATA_HASH_TABLE => Ok(JournalObjectType::DataHashTable),
        v if v == nom_object_type::FIELD_HASH_TABLE => Ok(JournalObjectType::FieldHashTable),
        v if v == nom_object_type::ENTRY_ARRAY => Ok(JournalObjectType::EntryArray),
        v if v == nom_object_type::TAG => Ok(JournalObjectType::Tag),
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
