#![no_main]
//! Fuzz target for `journald_binary::parse_entries`.
//!
//! Invariant: the arena walker must NEVER panic on arbitrary, attacker-crafted
//! input. `parse_entries` accepts a raw `&[u8]` (a whole `.journal` file), reads
//! a `header_size` field, then walks the object arena resolving Entry→Data item
//! offsets. Every integer read, offset, and object size in that walk comes from
//! the untrusted buffer; a hostile file can declare `size = u64::MAX`, point
//! items past EOF, or truncate mid-object. This target drives the full walk so
//! libFuzzer explores those paths — the class that already produced one overflow
//! panic (fixed in aff68e7).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Discarded result — we assert only the absence of a panic / OOB read.
    let _ = journald_binary::parse_entries(data);
});
