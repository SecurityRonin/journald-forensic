//! Magic byte scanning and entry carving for systemd journal files.
//!
//! All functions accept `&[u8]` slices — no file I/O.

use journald_binary::JOURNAL_MAGIC;

/// A carved object found by scanning raw bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CarvedEntry {
    pub offset: u64,
    pub object_type: u8,
    pub size: u64,
    pub raw: Vec<u8>,
}

/// Scan a byte slice for `LPKSHHRH` magic (journal file headers).
///
/// Returns the byte offsets where the magic was found.
pub fn scan_for_journal_magic(data: &[u8]) -> Vec<u64> {
    if data.len() < 8 {
        return Vec::new();
    }
    data.windows(8)
        .enumerate()
        .filter_map(|(i, w)| {
            if w == JOURNAL_MAGIC.as_ref() {
                #[allow(clippy::cast_possible_truncation)]
                Some(i as u64)
            } else {
                None
            }
        })
        .collect()
}

/// Scan for Entry object headers (type byte = 3) in a raw byte slice.
///
/// For each candidate position, check that the object header is plausible
/// (non-zero size, type = Entry). Returns the list of carved entries.
pub fn scan_for_entry_objects(data: &[u8]) -> Vec<CarvedEntry> {
    let mut out = Vec::new();
    if data.len() < 16 {
        return out;
    }
    let mut i = 0usize;
    while i + 16 <= data.len() {
        let buf = &data[i..];
        if buf[0] == 3 && is_plausible_object_header(buf) {
            let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            // Safe: we only process files that fit in memory (usize range)
            #[allow(clippy::cast_possible_truncation)]
            let end = ((i as u64).saturating_add(size) as usize).min(data.len());
            let raw = data[i..end].to_vec();
            out.push(CarvedEntry {
                #[allow(clippy::cast_possible_truncation)]
                offset: i as u64,
                object_type: 3,
                size,
                raw,
            });
            // Advance by size to skip this object, or by 1 if size is 0/huge
            #[allow(clippy::cast_possible_truncation)]
            let advance = (size as usize).max(1);
            i += advance;
        } else {
            i += 1;
        }
    }
    out
}

/// Returns `true` if the bytes at the start of `buf` look like a valid object header.
///
/// Criteria:
/// - At least 16 bytes available
/// - Type byte in 0..=7
/// - Size > 0
pub fn is_plausible_object_header(buf: &[u8]) -> bool {
    if buf.len() < 16 {
        return false;
    }
    let type_byte = buf[0];
    if type_byte > 7 {
        return false;
    }
    let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    size > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_empty_returns_empty() {
        assert!(scan_for_journal_magic(&[]).is_empty());
    }

    #[test]
    fn scan_finds_magic_at_offset_zero() {
        let mut buf = vec![0u8; 64];
        buf[..8].copy_from_slice(b"LPKSHHRH");
        let offsets = scan_for_journal_magic(&buf);
        assert_eq!(offsets, vec![0u64]);
    }

    #[test]
    fn scan_finds_magic_at_nonzero_offset() {
        let mut buf = vec![0u8; 64];
        buf[16..24].copy_from_slice(b"LPKSHHRH");
        let offsets = scan_for_journal_magic(&buf);
        assert_eq!(offsets, vec![16u64]);
    }

    #[test]
    fn scan_finds_multiple_magic_occurrences() {
        let mut buf = vec![0u8; 128];
        buf[0..8].copy_from_slice(b"LPKSHHRH");
        buf[64..72].copy_from_slice(b"LPKSHHRH");
        let offsets = scan_for_journal_magic(&buf);
        assert_eq!(offsets, vec![0u64, 64u64]);
    }

    #[test]
    fn is_plausible_object_header_accepts_valid_type() {
        let mut buf = [0u8; 16];
        buf[0] = 3; // Entry
        buf[8..16].copy_from_slice(&128u64.to_le_bytes()); // size = 128
        assert!(is_plausible_object_header(&buf));
    }

    #[test]
    fn is_plausible_object_header_rejects_zero_size() {
        let mut buf = [0u8; 16];
        buf[0] = 3; // Entry
        // size remains 0
        assert!(!is_plausible_object_header(&buf));
    }

    #[test]
    fn is_plausible_object_header_rejects_unknown_type() {
        let mut buf = [0u8; 16];
        buf[0] = 99; // unknown
        buf[8..16].copy_from_slice(&128u64.to_le_bytes());
        assert!(!is_plausible_object_header(&buf));
    }

    #[test]
    fn is_plausible_object_header_too_short_returns_false() {
        assert!(!is_plausible_object_header(&[3u8; 8]));
    }

    #[test]
    fn scan_for_entry_objects_finds_type3_header() {
        // Build a minimal byte buffer with an Entry object header at offset 32
        let mut buf = vec![0u8; 64];
        buf[32] = 3; // type = Entry
        buf[33] = 0; // flags
        // reserved bytes 34..39 remain 0
        buf[40..48].copy_from_slice(&64u64.to_le_bytes()); // size = 64
        let entries = scan_for_entry_objects(&buf);
        assert!(!entries.is_empty());
        let e = entries.iter().find(|e| e.offset == 32).expect("entry at offset 32");
        assert_eq!(e.object_type, 3);
        assert_eq!(e.size, 64);
    }

    #[test]
    fn scan_for_entry_objects_empty_returns_empty() {
        assert!(scan_for_entry_objects(&[]).is_empty());
    }
}
