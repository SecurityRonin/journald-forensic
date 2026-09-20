//! Malformed / adversarial input hardening for `parse_entries`.
//!
//! Property under test: `parse_entries` must NEVER panic and must degrade to a
//! (possibly empty) `Vec` on arbitrary, attacker-crafted bytes — the class that
//! produced the `align8` overflow panic (fixed in aff68e7). These are
//! deterministic, committed regression tests; the continuous backstop is the
//! `fuzz_parse_entries` cargo-fuzz target (see `fuzz/`).
//!
//! Every buffer here is built byte-exact in-source (no external file), so the
//! suite is reproducible and needs no LGPL systemd fuzz seeds — a deliberate
//! license choice (this repo is Apache-2.0; see `docs/validation.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use journald_binary::parse_entries;

const MAGIC: &[u8] = b"LPKSHHRH";

/// Deterministic LCG (Numerical Recipes constants) → reproducible pseudo-garbage.
fn lcg_fill(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// A 240-byte header whose `header_size` (offset 88) puts the arena at 240.
fn base_header() -> Vec<u8> {
    let mut h = vec![0u8; 240];
    h[..8].copy_from_slice(MAGIC);
    h[88..96].copy_from_slice(&240u64.to_le_bytes());
    h
}

#[test]
fn empty_and_all_truncation_points_below_min_header_return_empty() {
    // Every length 0..=95 is below MIN_HEADER (96) → early empty return, no panic.
    for len in 0..96usize {
        let buf = vec![0u8; len];
        assert!(parse_entries(&buf).is_empty(), "len {len} must be empty");
    }
    // Same, but with valid magic present.
    for len in 8..96usize {
        let mut buf = vec![0u8; len];
        buf[..8].copy_from_slice(MAGIC);
        assert!(parse_entries(&buf).is_empty(), "magic+{len} must be empty");
    }
}

#[test]
fn extreme_header_size_values_do_not_panic() {
    for hs in [
        0u64,
        1,
        95,
        96,
        239,
        240,
        241,
        1_000_000,
        u64::MAX,
        u64::MAX - 7,
    ] {
        let mut buf = vec![0u8; 512];
        buf[..8].copy_from_slice(MAGIC);
        buf[88..96].copy_from_slice(&hs.to_le_bytes());
        let _ = parse_entries(&buf); // must return, not panic
    }
}

#[test]
fn all_0xff_arena_does_not_panic() {
    // An arena of 0xFF makes every object claim type 0xFF (unparseable) and
    // size u64::MAX (the overflow-prone path). Must not panic.
    let mut buf = base_header();
    buf.extend(std::iter::repeat(0xFFu8).take(4096));
    let _ = parse_entries(&buf);
}

#[test]
fn pseudo_random_garbage_of_many_lengths_does_not_panic() {
    for seed in 0..64u64 {
        for len in [96usize, 128, 240, 256, 512, 1024, 4096, 8191] {
            let mut buf = lcg_fill(seed, len);
            if len >= 8 {
                buf[..8].copy_from_slice(MAGIC); // exercise the past-magic paths too
            }
            let _ = parse_entries(&buf);
        }
    }
}

#[test]
fn entry_with_oversized_size_and_item_count_does_not_panic() {
    // Entry at 240 declaring size = u64::MAX so the item loop bound
    // (item_pos + 16 <= obj_end) is driven to the buffer edge.
    let mut buf = base_header();
    buf.resize(4096, 0);
    buf[240] = 3; // Entry
    buf[248..256].copy_from_slice(&u64::MAX.to_le_bytes());
    let _ = parse_entries(&buf);
}

#[test]
fn entry_items_at_every_offset_boundary_do_not_panic() {
    // Sweep an Entry's single item data_offset across values around EOF, u64::MAX,
    // and self-references — each drives a different defensive arm.
    let len = 1024u64;
    for item_off in [
        0u64,
        16,
        96,
        239,
        240,
        304,
        len - 16,
        len - 1,
        len,
        len + 1,
        u64::MAX,
        u64::MAX - 16,
    ] {
        let mut buf = base_header();
        buf.resize(len as usize, 0);
        let entry_off = 240usize;
        buf[entry_off] = 3; // Entry
        buf[entry_off + 8..entry_off + 16].copy_from_slice(&128u64.to_le_bytes());
        buf[entry_off + 64..entry_off + 72].copy_from_slice(&item_off.to_le_bytes());
        let _ = parse_entries(&buf);
    }
}

#[test]
fn data_object_with_extreme_size_does_not_panic() {
    // Entry item points at a Data object whose declared size is u64::MAX, driving
    // the payload_end = data_offset + size .min(len) saturation path.
    let mut buf = base_header();
    buf.resize(1024, 0);
    let entry_off = 240usize;
    let data_off = 512u64;
    buf[entry_off] = 3;
    buf[entry_off + 8..entry_off + 16].copy_from_slice(&128u64.to_le_bytes());
    buf[entry_off + 64..entry_off + 72].copy_from_slice(&data_off.to_le_bytes());
    buf[data_off as usize] = 1; // Data
    buf[data_off as usize + 8..data_off as usize + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    let _ = parse_entries(&buf);
}

#[test]
fn self_referential_and_cyclic_offsets_terminate_without_panic() {
    // A Data object whose item points back into its own header region. The walk
    // is bounded by the arena scan (pos advances by align8(size) >= 8), so a
    // crafted cycle cannot loop forever — confirm it terminates and returns.
    let mut buf = base_header();
    buf.resize(512, 0);
    let entry_off = 240usize;
    buf[entry_off] = 3;
    buf[entry_off + 8..entry_off + 16].copy_from_slice(&128u64.to_le_bytes());
    // item points at the Entry itself (offset 240) → non-Data, no fields, no loop.
    buf[entry_off + 64..entry_off + 72].copy_from_slice(&(entry_off as u64).to_le_bytes());
    let entries = parse_entries(&buf);
    // One Entry object is present; it simply yields no fields.
    assert_eq!(entries.len(), 1);
    assert!(entries[0].fields.is_empty());
}

#[test]
fn zero_size_objects_do_not_stall_the_walk() {
    // A long run of zero bytes after the header = objects with size 0 (< 16);
    // the walk must step forward 8 bytes each time and terminate, not spin.
    let mut buf = base_header();
    buf.resize(240 + 4096, 0);
    let entries = parse_entries(&buf);
    assert!(entries.is_empty());
}
