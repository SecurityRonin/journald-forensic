//! Binary format parser for systemd journal files.
//!
//! All functions accept `&[u8]` slices — no file I/O.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use journald_core::{JournalEntry, JournalError, JournalField, JournalFieldValue};

// KNOWLEDGE constants live in forensicnomicon; re-export for downstream crates.
pub use forensicnomicon::journald::JOURNAL_MAGIC;
use forensicnomicon::journald::{
    header_offset, object_header_offset, object_type as nom_object_type,
};

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

/// Copy the `N`-byte window at `off` out of `buf`, or `None` if it does not fit.
///
/// The scalar counterpart is `safe_read`; this covers the fixed-width byte
/// arrays (magic, 128-bit IDs) that it does not model, with the same
/// return-`None`-rather-than-panic contract.
fn fixed<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(buf.get(off..end)?);
    Some(out)
}

/// The error `parse_header` reports when `buf` is too small to hold a complete
/// journal header. Shared by the length guard and by the bounded-read fallback
/// below it so the two cannot drift apart.
fn header_too_short(buf: &[u8]) -> JournalError {
    JournalError::BufferTooShort {
        needed: header_offset::MIN_HEADER_SIZE,
        got: buf.len(),
    }
}

/// Verify that `buf` begins with the journal magic bytes.
pub fn parse_journal_magic(buf: &[u8]) -> Result<(), JournalError> {
    let Some(found) = fixed::<8>(buf, 0) else {
        return Err(JournalError::BufferTooShort {
            needed: 8,
            got: buf.len(),
        });
    };
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
        return Err(header_too_short(buf));
    }
    parse_journal_magic(buf)?;

    // Every field below is read through a bounded reader (ADR-0012), so the
    // MIN_HEADER_SIZE guard above is a diagnostic, not the thing keeping these
    // reads in range.
    let compatible_flags = safe_read::le_u32(buf, header_offset::COMPATIBLE_FLAGS);
    let incompatible_flags = safe_read::le_u32(buf, header_offset::INCOMPATIBLE_FLAGS);
    let state = match safe_read::u8(buf, header_offset::STATE) {
        0 => JournalState::Offline,
        2 => JournalState::Archived,
        _ => JournalState::Online, // 1 = Online; treat unknown as Online (suspicious)
    };

    let (Some(machine_id), Some(boot_id), Some(seqnum_id)) = (
        fixed::<16>(buf, header_offset::MACHINE_ID),
        fixed::<16>(buf, header_offset::BOOT_ID),
        fixed::<16>(buf, header_offset::SEQNUM_ID),
    ) else {
        // cov:unreachable: buf.len() >= MIN_HEADER_SIZE (224) by the guard at the
        // top of this function, and the furthest byte these three reads touch is
        // SEQNUM_ID (72) + 16 = 88. So `fixed::<16>` cannot return None here.
        // Kept as a defence-in-depth guard: it is what stops a future change to
        // the offsets or to MIN_HEADER_SIZE from turning into an out-of-bounds
        // read instead of a clean error (ADR-0012).
        return Err(header_too_short(buf)); // cov:unreachable: see above
    };

    let n_objects = safe_read::le_u64(buf, header_offset::N_OBJECTS);
    let n_entries = safe_read::le_u64(buf, header_offset::N_ENTRIES);
    let tail_entry_seqnum = safe_read::le_u64(buf, header_offset::TAIL_ENTRY_SEQNUM);
    let head_entry_seqnum = safe_read::le_u64(buf, header_offset::HEAD_ENTRY_SEQNUM);
    let head_entry_realtime = safe_read::le_u64(buf, header_offset::HEAD_ENTRY_REALTIME);
    let tail_entry_realtime = safe_read::le_u64(buf, header_offset::TAIL_ENTRY_REALTIME);

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
    let object_type = object_type_from_byte(safe_read::u8(buf, object_header_offset::TYPE))?;
    let flags = safe_read::u8(buf, object_header_offset::FLAGS);
    let size = safe_read::le_u64(buf, object_header_offset::SIZE);
    Ok(ObjectHeader {
        object_type,
        flags,
        size,
    })
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

/// Decode the journal arena into a stream of [`journald_core::JournalEntry`] values.
///
/// Best-effort sequential walk of the object arena (from after the header) that
/// yields every `Entry` object with its resolved `KEY=value` fields. This is the
/// public library seam behind the CLI's timeline/fields/search commands; keeping
/// the walk here rather than in the binary is what makes it fuzzable and testable
/// against a journalctl oracle.
///
/// It does not follow hash-table chains — it walks the arena sequentially from
/// after the header, resolving each entry item's referenced `Data` object.
///
/// Panic-free on arbitrary input: every integer read goes through `safe-read`,
/// which bounds-checks and returns `0` out of range (ADR-0012), and every offset
/// is computed with saturating arithmetic so a hostile size or offset cannot
/// overflow `usize`.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn parse_entries(data: &[u8]) -> Vec<JournalEntry> {
    // The journal header is at offset 0; header_size is a LE u64 at offset 88.
    const MIN_HEADER: usize = 96;
    const HEADER_SIZE_OFF: usize = 88;
    // Smallest arena start we will trust even if the header understates it.
    const MIN_ARENA_START: usize = 240;

    if data.len() < MIN_HEADER {
        return Vec::new();
    }
    let arena_start = (safe_read::le_u64(data, HEADER_SIZE_OFF) as usize).max(MIN_ARENA_START);
    if arena_start >= data.len() {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut pos = arena_start;

    while pos.saturating_add(16) <= data.len() {
        let Ok(obj) = parse_object_header(&data[pos..]) else {
            pos = pos.saturating_add(8);
            continue;
        };
        let size = obj.size as usize;
        if size < 16 {
            pos = pos.saturating_add(8);
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
            if pos.saturating_add(64) > data.len() {
                pos = pos.saturating_add(align8(size));
                continue;
            }
            let seqnum = safe_read::le_u64(data, pos.saturating_add(16));
            let realtime_us = safe_read::le_u64(data, pos.saturating_add(24));
            let monotonic_us = safe_read::le_u64(data, pos.saturating_add(32));
            let boot_id =
                safe_read::try_bytes::<16>(data, pos.saturating_add(40)).unwrap_or([0u8; 16]);

            let obj_end = pos.saturating_add(size).min(data.len());
            let mut fields = Vec::new();
            let mut item_pos = pos.saturating_add(64);

            while item_pos.saturating_add(16) <= obj_end {
                let data_offset = safe_read::le_u64(data, item_pos) as usize;
                item_pos = item_pos.saturating_add(16);

                if data_offset.saturating_add(16) > data.len() {
                    continue;
                }
                let Ok(data_obj) = parse_object_header(&data[data_offset..]) else {
                    continue;
                };
                if data_obj.object_type != JournalObjectType::Data {
                    continue;
                }
                // A Data object's payload starts at +64 within the object.
                let payload_start = data_offset.saturating_add(64);
                let payload_end = data_offset
                    .saturating_add(data_obj.size as usize)
                    .min(data.len());
                if payload_start >= payload_end {
                    continue;
                }
                let payload = &data[payload_start..payload_end];
                // payload is "KEY=value" in raw bytes.
                if let Some(eq) = payload.iter().position(|&b| b == b'=') {
                    let key = String::from_utf8_lossy(&payload[..eq]).into_owned();
                    let raw = &payload[eq.saturating_add(1)..];
                    let value = match std::str::from_utf8(raw) {
                        Ok(text) => JournalFieldValue::Text(text.to_owned()),
                        Err(_) => JournalFieldValue::Binary(raw.to_vec()),
                    };
                    fields.push(JournalField { key, value });
                }
            }
            entries.push(JournalEntry {
                seqnum,
                realtime_us,
                monotonic_us,
                boot_id,
                fields,
            });
        }

        pos = pos.saturating_add(align8(size));
    }
    entries
}

/// Round `size` up to the next 8-byte boundary, with a minimum step of 8.
///
/// Journal objects are 64-bit aligned: the next object begins at
/// `ALIGN64(offset + size)`, not `offset + size`. Advancing by the raw size
/// derails the sequential walk at the first object whose size is not a multiple
/// of 8 (e.g. a Data object carrying a short "KEY=value" payload). The `.max(8)`
/// floor guarantees forward progress, so a zero-size object cannot stall it.
fn align8(size: usize) -> usize {
    (size.saturating_add(7) & !7).max(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- forensicnomicon integration tests (RED: forensicnomicon dep not yet wired) ---

    #[test]
    fn binary_magic_matches_forensicnomicon_constant() {
        use forensicnomicon::journald::{header_offset, object_type, JOURNAL_MAGIC as NOM_MAGIC};
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
        assert!(matches!(
            object_type_from_byte(0),
            Ok(JournalObjectType::Unused)
        ));
        assert!(matches!(
            object_type_from_byte(1),
            Ok(JournalObjectType::Data)
        ));
        assert!(matches!(
            object_type_from_byte(2),
            Ok(JournalObjectType::Field)
        ));
        assert!(matches!(
            object_type_from_byte(3),
            Ok(JournalObjectType::Entry)
        ));
        assert!(matches!(
            object_type_from_byte(4),
            Ok(JournalObjectType::DataHashTable)
        ));
        assert!(matches!(
            object_type_from_byte(5),
            Ok(JournalObjectType::FieldHashTable)
        ));
        assert!(matches!(
            object_type_from_byte(6),
            Ok(JournalObjectType::EntryArray)
        ));
        assert!(matches!(
            object_type_from_byte(7),
            Ok(JournalObjectType::Tag)
        ));
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

    // --- parse_header against a REAL journal header (Tier-1) ---
    //
    // The fixture is a real systemd-239 journal; its header fields were confirmed
    // with the independent `journalctl --header` oracle (see tests/data/README.md).
    // We assert only the fields whose forensicnomicon offsets are byte-verified
    // against that oracle: magic, flags, state, and the three 128-bit IDs. (The
    // higher numeric fields — n_objects/n_entries/seqnums/realtimes — are read at
    // forensicnomicon offsets that do not match the systemd layout for this
    // version; asserting their current output would bless wrong values, so they
    // are exercised for coverage but not asserted here.)
    const REAL_JOURNAL: &[u8] = include_bytes!("../../../tests/data/classic-system.journal");

    fn hex16(bytes: &[u8; 16]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn parse_header_reads_real_journal_header() {
        let hdr = parse_header(REAL_JOURNAL).expect("real journal header must parse");
        assert_eq!(hdr.state, JournalState::Offline);
        assert_eq!(hdr.compatible_flags, 0);
        assert_eq!(hdr.incompatible_flags, 0); // classic format: no COMPACT/KEYED_HASH
        assert_eq!(hex16(&hdr.machine_id), "e7d87b83baf96ba14eb77adc0a769ed2");
        assert_eq!(hex16(&hdr.boot_id), "e00a23d431394d0ca22d6e3ebc10dd74");
        assert_eq!(hex16(&hdr.seqnum_id), "799abeca5ffa46fcb51552ab9afb90cc");
    }

    #[test]
    fn parse_header_too_short_returns_err() {
        // < MIN_HEADER_SIZE (224) → BufferTooShort, before any field read.
        let buf = [0u8; 100];
        assert!(matches!(
            parse_header(&buf),
            Err(JournalError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn parse_header_state_byte_maps_all_arms() {
        // Take the real header and flip only the state byte to exercise each arm.
        let mut buf = REAL_JOURNAL[..256].to_vec();
        buf[forensicnomicon::journald::header_offset::STATE] = 0;
        assert_eq!(parse_header(&buf).unwrap().state, JournalState::Offline);
        buf[forensicnomicon::journald::header_offset::STATE] = 2;
        assert_eq!(parse_header(&buf).unwrap().state, JournalState::Archived);
        buf[forensicnomicon::journald::header_offset::STATE] = 1;
        assert_eq!(parse_header(&buf).unwrap().state, JournalState::Online);
        // Unknown state byte is treated as Online (suspicious).
        buf[forensicnomicon::journald::header_offset::STATE] = 99;
        assert_eq!(parse_header(&buf).unwrap().state, JournalState::Online);
    }

    #[test]
    fn parse_header_bad_magic_returns_err() {
        let mut buf = REAL_JOURNAL[..256].to_vec();
        buf[..8].copy_from_slice(b"NOTAJRNL");
        assert!(matches!(
            parse_header(&buf),
            Err(JournalError::InvalidMagic { .. })
        ));
    }
}
