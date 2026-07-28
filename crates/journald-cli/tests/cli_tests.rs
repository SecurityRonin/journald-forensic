use assert_cmd::Command;
use std::io::Write;

fn jd() -> Command {
    Command::cargo_bin("jd4n6").unwrap()
}

/// Path to the committed real systemd-239 journal fixture (repo-root tests/data).
/// Ground truth verified with the `journalctl` oracle — see tests/data/README.md.
fn real_journal() -> String {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/data/classic-system.journal"
    )
    .to_string()
}

/// Write `bytes` to a temp file and return the tempdir (keep it alive) + path.
fn temp_file(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(bytes).unwrap();
    drop(f);
    (dir, path)
}

const MAGIC: &[u8] = b"LPKSHHRH";

#[test]
fn jd_help_exits_0() {
    jd().arg("--help").assert().success();
}

#[test]
fn jd_version_exits_0() {
    jd().arg("--version").assert().success();
}

#[test]
fn jd_timeline_help_exits_0() {
    jd().args(["timeline", "--help"]).assert().success();
}

#[test]
fn jd_fields_help_exits_0() {
    jd().args(["fields", "--help"]).assert().success();
}

#[test]
fn jd_search_help_exits_0() {
    jd().args(["search", "--help"]).assert().success();
}

#[test]
fn jd_nonexistent_path_exits_nonzero() {
    jd().args(["timeline", "/nonexistent/path/to/journal.journal"])
        .assert()
        .failure();
}

#[test]
fn jd_empty_file_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.journal");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(&[]).unwrap();
    drop(f);
    jd().args(["timeline", path.to_str().unwrap()])
        .assert()
        .failure();
}

// --- Happy paths against the REAL journal fixture (Tier-1) ---
// Oracle (journalctl): 30 entry objects, 21 with SYSLOG_IDENTIFIER=jdtest.

#[test]
fn jd_timeline_emits_all_entries() {
    let out = jd()
        .args(["timeline", &real_journal()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        30,
        "expected 30 timeline entries (journalctl oracle)"
    );
    // Each line must be a JSON object carrying seqnum + realtime_us.
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
        assert!(v.get("seqnum").is_some());
        assert!(v.get("realtime_us").is_some());
    }
    assert!(stdout.contains("fixture message NUM 1 ALPHA BRAVO"));
}

#[test]
fn jd_fields_lists_known_field_names() {
    let out = jd()
        .args(["fields", &real_journal()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    // Fields are printed sorted; must include core journald keys.
    for key in [
        "MESSAGE",
        "PRIORITY",
        "SYSLOG_IDENTIFIER",
        "_PID",
        "_BOOT_ID",
    ] {
        assert!(stdout.lines().any(|l| l == key), "missing field {key}");
    }
}

#[test]
fn jd_search_matches_syslog_identifier() {
    let out = jd()
        .args(["search", &real_journal(), "SYSLOG_IDENTIFIER=jdtest"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(
        stdout.lines().count(),
        21,
        "expected 21 jdtest matches (journalctl oracle)"
    );
    assert!(stdout.contains("fixture ERROR message CHARLIE"));
}

#[test]
fn jd_search_no_match_emits_nothing() {
    jd().args([
        "search",
        &real_journal(),
        "SYSLOG_IDENTIFIER=does-not-exist",
    ])
    .assert()
    .success()
    .stdout("");
}

// --- Edge / error paths on crafted byte buffers (bytes live in this source) ---

#[test]
fn jd_search_filter_without_equals_errors() {
    // filter must be FIELD=VALUE; a bare token has no '=' → error, exit 1.
    jd().args(["search", &real_journal(), "NOEQUALSHERE"])
        .assert()
        .failure();
}

#[test]
fn jd_wrong_magic_exits_nonzero() {
    let (_dir, path) = temp_file("bad.journal", b"NOTAJRNL and some trailing bytes");
    jd().args(["timeline", path.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn jd_valid_magic_but_below_min_header_reports_no_entries() {
    // Valid magic but shorter than MIN_HEADER (96) → parse_entries returns empty,
    // exercising the len < MIN_HEADER early-return and the "no entries" branch.
    let mut buf = MAGIC.to_vec();
    buf.extend_from_slice(&[0u8; 80]); // total 88 bytes < 96
    let (_dir, path) = temp_file("short.journal", &buf);
    let out = jd()
        .args(["timeline", path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8(out).unwrap();
    assert!(stderr.contains("no entries"), "stderr was: {stderr}");
}

#[test]
fn jd_valid_magic_huge_header_size_reports_no_entries() {
    // header_size (offset 88) set absurdly large → arena_start >= data.len(),
    // exercising the arena_start bounds early-return.
    let mut buf = vec![0u8; 240];
    buf[..8].copy_from_slice(MAGIC);
    buf[88..96].copy_from_slice(&1_000_000u64.to_le_bytes());
    let (_dir, path) = temp_file("hugehdr.journal", &buf);
    jd().args(["fields", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(""); // no fields, no entries
}

// --- Malformed-arena robustness (attacker-crafted journals) ---
// These drive parse_entries' defensive recovery arms. The reader must never panic
// and must degrade to "no entries" rather than crash or produce garbage. The bytes
// are constructed here (committed with the test), so the gate needs no external
// file. Layout constants mirror the systemd on-disk object header (type@0, size@8).

/// 240-byte header: magic + `header_size`=240 so the `parse_entries` arena starts at 240.
fn base_header() -> Vec<u8> {
    let mut h = vec![0u8; 240];
    h[..8].copy_from_slice(MAGIC);
    h[88..96].copy_from_slice(&240u64.to_le_bytes());
    h
}

/// A 16-byte object header: type byte + little-endian u64 size at offset 8.
fn obj_header(ty: u8, size: u64) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = ty;
    o[8..16].copy_from_slice(&size.to_le_bytes());
    o
}

#[test]
fn jd_arena_with_unknown_object_type_does_not_crash() {
    // An object whose type byte is out of range (99 > 7) makes parse_object_header
    // fail; parse_entries must step forward 8 bytes and keep walking, not abort.
    let mut buf = base_header();
    buf.extend_from_slice(&obj_header(99, 32)); // bad type at offset 240
    let (_dir, path) = temp_file("badtype.journal", &buf);
    jd().args(["timeline", path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn jd_entry_truncated_at_eof_does_not_crash() {
    // An Entry header whose body runs past EOF (pos+64 > len) must be skipped.
    let mut buf = base_header();
    buf.extend_from_slice(&obj_header(3, 64)); // Entry at 240, claims size 64
    buf.extend_from_slice(&[0u8; 4]); // only 4 body bytes → pos+64 overruns
    let (_dir, path) = temp_file("truncentry.journal", &buf);
    jd().args(["timeline", path.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn jd_entry_items_pointing_at_bad_data_offsets_do_not_crash() {
    // One Entry with four items, each pointing at a different malformed target,
    // exercising every per-item defensive arm in a single crafted journal:
    //   item0 → data_offset past EOF
    //   item1 → in-bounds offset whose object type is unknown
    //   item2 → in-bounds object that is not a Data object (an Entry)
    //   item3 → a Data object whose size is too small to hold any payload
    const ENTRY_OFF: usize = 240;
    const ENTRY_SIZE: u64 = 128; // header(16) + body to 4 items ending at 368
    const T_BADTYPE: usize = 368;
    const T_ENTRY: usize = 384;
    const T_EMPTY_DATA: usize = 400;
    const LEN: usize = 416;

    let mut buf = base_header();
    buf.resize(LEN, 0);
    buf[ENTRY_OFF..ENTRY_OFF + 16].copy_from_slice(&obj_header(3, ENTRY_SIZE));
    // items start at ENTRY_OFF+64 = 304; each item is (offset u64, hash u64) = 16 bytes
    let items_start = ENTRY_OFF + 64;
    let set_item = |b: &mut [u8], idx: usize, data_offset: u64| {
        let o = items_start + idx * 16;
        b[o..o + 8].copy_from_slice(&data_offset.to_le_bytes());
    };
    set_item(&mut buf, 0, 0xFFFF_FFFF); // past EOF  → line 150
    set_item(&mut buf, 1, T_BADTYPE as u64); // bad type → line 153
    set_item(&mut buf, 2, T_ENTRY as u64); // not Data → line 156
    set_item(&mut buf, 3, T_EMPTY_DATA as u64); // empty payload → line 162
    buf[T_BADTYPE..T_BADTYPE + 16].copy_from_slice(&obj_header(99, 32));
    buf[T_ENTRY..T_ENTRY + 16].copy_from_slice(&obj_header(3, 64));
    buf[T_EMPTY_DATA..T_EMPTY_DATA + 16].copy_from_slice(&obj_header(1, 20)); // Data, size<64

    let (_dir, path) = temp_file("baditems.journal", &buf);
    // Degrades cleanly: the entry yields no valid fields, so no output, exit 0.
    jd().args(["timeline", path.to_str().unwrap()])
        .assert()
        .success();
}
