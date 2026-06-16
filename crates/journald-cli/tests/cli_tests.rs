use assert_cmd::Command;
use std::io::Write;

fn jd() -> Command {
    Command::cargo_bin("jd4n6").unwrap()
}

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
