//! End-to-end tests of the `veil` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("veil-{name}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn veil(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Splits `contents` 3-of-5 into `dir` and returns the share paths in index order.
fn split(dir: &TempDir, contents: &[u8]) -> Vec<String> {
    let input = dir.join("input");
    fs::write(&input, contents).unwrap();
    let out = veil(&["split", &input, "-o", dir.0.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let shares = files_in(dir.0.to_str().unwrap(), ".veil");
    assert_eq!(shares.len(), 5);
    shares
}

/// Paths of the files in `dir` ending in `suffix`, sorted.
fn files_in(dir: &str, suffix: &str) -> Vec<String> {
    let mut files: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path().to_str().unwrap().to_owned())
        .filter(|p| p.ends_with(suffix))
        .collect();
    files.sort();
    files
}

#[test]
fn any_three_shares_rebuild_the_file() {
    let dir = TempDir::new("roundtrip");
    let contents = b"the launch code is 0000";
    let s = split(&dir, contents);
    for (i, picked) in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]]
        .iter()
        .enumerate()
    {
        let output = dir.join(&format!("out{i}"));
        let out = veil(&[
            "combine",
            &s[picked[0]],
            &s[picked[1]],
            &s[picked[2]],
            "-o",
            &output,
        ]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(fs::read(&output).unwrap(), contents);
    }
}

#[test]
fn two_shares_are_not_enough() {
    let dir = TempDir::new("two");
    let s = split(&dir, b"secret");
    let out = veil(&["combine", &s[0], &s[4], "-o", &dir.join("out")]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("need 3 shares, got 2"));
    assert!(!Path::new(&dir.join("out")).exists());
}

#[test]
fn tampered_share_is_rejected_and_named() {
    let dir = TempDir::new("tamper");
    let s = split(&dir, b"secret");
    let mut bytes = fs::read(&s[1]).unwrap();
    bytes[5000] ^= 0x41;
    fs::write(&s[1], bytes).unwrap();
    let out = veil(&["combine", &s[0], &s[1], &s[2], "-o", &dir.join("out")]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("tamper detected"), "{err}");
    assert!(err.contains("share 2 was rejected by 2 of 2"), "{err}");
    assert!(!Path::new(&dir.join("out")).exists());
}

#[test]
fn check_cross_verifies_without_rebuilding() {
    let dir = TempDir::new("check");
    let s = split(&dir, b"secret");
    let out = veil(&["check", &s[1], &s[3]]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("all 2 cross-checks passed"));
}

#[test]
fn combine_to_stdout() {
    let dir = TempDir::new("stdout");
    let s = split(&dir, b"to stdout");
    let out = veil(&["combine", &s[2], &s[3], &s[4], "-o", "-"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"to stdout");
}

#[test]
fn oversized_file_is_refused() {
    let dir = TempDir::new("big");
    let input = dir.join("input");
    fs::write(&input, vec![0u8; 10_241]).unwrap();
    let out = veil(&["split", &input, "-o", dir.0.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("larger than 10240 bytes"));
}

#[test]
fn existing_output_is_never_overwritten() {
    let dir = TempDir::new("overwrite");
    let s = split(&dir, b"secret");
    let output = dir.join("out");
    fs::write(&output, b"keep me").unwrap();
    let out = veil(&["combine", &s[0], &s[1], &s[2], "-o", &output]);
    assert!(!out.status.success());
    assert_eq!(fs::read(&output).unwrap(), b"keep me");
}

#[test]
fn bad_threshold_is_a_usage_error() {
    let dir = TempDir::new("params");
    let input = dir.join("input");
    fs::write(&input, b"x").unwrap();
    let out = veil(&["split", &input, "-k", "6", "-n", "5"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn refresh_keeps_the_file_and_epochs_stop_mixing() {
    let dir = TempDir::new("refresh");
    let contents = b"rotate me";
    let old = split(&dir, contents);
    let next = dir.join("e1");
    fs::create_dir(&next).unwrap();
    // Out of order on purpose: each mask must still reach its own share.
    let mut args = vec!["refresh"];
    args.extend(old.iter().rev().map(String::as_str));
    args.extend(["-o", next.as_str()]);
    let out = veil(&args);
    assert!(out.status.success(), "{}", stderr(&out));

    let mut new: Vec<String> = fs::read_dir(&next)
        .unwrap()
        .map(|e| e.unwrap().path().to_str().unwrap().to_owned())
        .collect();
    new.sort();
    assert_eq!(new.len(), 5);
    assert!(new.iter().all(|p| p.contains("-e1-")), "{new:?}");

    let output = dir.join("out");
    let out = veil(&["combine", &new[0], &new[2], &new[4], "-o", &output]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fs::read(&output).unwrap(), contents);

    let out = veil(&[
        "combine",
        &old[0],
        &new[1],
        &new[2],
        "-o",
        &dir.join("mixed"),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("different splits or epochs"));
}

#[test]
fn refresh_needs_every_share() {
    let dir = TempDir::new("refresh-partial");
    let s = split(&dir, b"secret");
    let out = veil(&[
        "refresh",
        &s[0],
        &s[1],
        &s[2],
        &s[3],
        "-o",
        dir.0.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("need 5 shares, got 4"));
}

/// The ceremony with the shares kept apart: each vault has its own directory, and every command
/// touches one share, or only keycards, at a time.
#[test]
fn ceremony_with_shares_kept_apart() {
    let dir = TempDir::new("ceremony");
    let contents = b"no two shares ever met";
    let old = split(&dir, contents);
    let vaults: Vec<String> = (1..=5).map(|x| dir.join(&format!("vault{x}"))).collect();
    let dealer = dir.join("dealer");
    for d in vaults.iter().chain([&dealer]) {
        fs::create_dir(d).unwrap();
    }

    for (share, vault) in old.iter().zip(&vaults) {
        let out = veil(&["keycard", share, "-o", vault]);
        assert!(out.status.success(), "{}", stderr(&out));
    }
    let mut args = vec!["deal"];
    let cards: Vec<String> = vaults
        .iter()
        .flat_map(|v| files_in(v, ".veilkey"))
        .collect();
    args.extend(cards.iter().map(String::as_str));
    args.extend(["-o", dealer.as_str()]);
    let out = veil(&args);
    assert!(out.status.success(), "{}", stderr(&out));

    let masks = files_in(&dealer, ".veilmask");
    for ((share, mask), vault) in old.iter().zip(&masks).zip(&vaults) {
        let out = veil(&["apply", share, mask, "-o", vault]);
        assert!(out.status.success(), "{}", stderr(&out));
    }
    let new: Vec<String> = vaults.iter().flat_map(|v| files_in(v, ".veil")).collect();
    assert_eq!(new.len(), 5);
    assert!(new.iter().all(|p| p.contains("-e1-")), "{new:?}");

    let output = dir.join("out");
    let out = veil(&["combine", &new[1], &new[3], &new[4], "-o", &output]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fs::read(&output).unwrap(), contents);
}

#[test]
fn apply_refuses_another_vaults_mask() {
    let dir = TempDir::new("wrong-mask");
    let s = split(&dir, b"secret");
    let work = dir.join("work");
    fs::create_dir(&work).unwrap();
    let mut args = vec!["keycard"];
    args.extend(s.iter().map(String::as_str));
    args.extend(["-o", work.as_str()]);
    assert!(veil(&args).status.success());
    let mut args = vec!["deal"];
    let cards = files_in(&work, ".veilkey");
    args.extend(cards.iter().map(String::as_str));
    args.extend(["-o", work.as_str()]);
    assert!(veil(&args).status.success());

    let masks = files_in(&work, ".veilmask");
    let out = veil(&["apply", &s[0], &masks[1], "-o", &work]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("mask was not made for this share"),
        "{}",
        stderr(&out)
    );
    assert!(files_in(&work, ".veil").is_empty());
}

fn veil_with_stdin(args: &[&str], input: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Simulated hardware noise: a fixed pseudorandom stream standing in for a device.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0u64;
    (0..len)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

fn dice() -> String {
    (0..272)
        .map(|i| char::from(b'1' + (i * 5 % 6) as u8))
        .collect()
}

#[test]
fn dice_seed_and_hardware_noise_drive_a_split() {
    let dir = TempDir::new("hardware");
    let seed = dir.join("seed.txt");
    let out = veil_with_stdin(&["seed", "-o", &seed], &dice());
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&seed).unwrap().trim().len(), 160);

    let raw = dir.join("noise.bin");
    fs::write(&raw, noise(200_000)).unwrap();
    let input = dir.join("input");
    fs::write(&input, b"real noise, real dice").unwrap();
    let shares = dir.join("shares");
    fs::create_dir(&shares).unwrap();
    let out = veil(&[
        "split",
        &input,
        "-o",
        &shares,
        "--entropy",
        &raw,
        "--min-entropy",
        "7.5",
        "--seed",
        &seed,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hardware noise XOR the OS generator"),
        "{stdout}"
    );
    assert!(
        stdout.contains("the extractor seed came from dice"),
        "{stdout}"
    );

    let s = files_in(&shares, ".veil");
    let output = dir.join("out");
    let out = veil(&["combine", &s[0], &s[2], &s[4], "-o", &output]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fs::read(&output).unwrap(), b"real noise, real dice");
}

#[test]
fn stuck_hardware_source_stops_the_split() {
    let dir = TempDir::new("stuck");
    let raw = dir.join("stuck.bin");
    fs::write(&raw, vec![0x55u8; 200_000]).unwrap();
    let input = dir.join("input");
    fs::write(&input, b"x").unwrap();
    let out = veil(&[
        "split",
        &input,
        "-o",
        &dir.join(""),
        "--entropy",
        &raw,
        "--min-entropy",
        "7",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("failed its health tests"),
        "{}",
        stderr(&out)
    );
    assert!(files_in(dir.0.to_str().unwrap(), ".veil").is_empty());
}

#[test]
fn hardware_source_that_runs_dry_stops_the_split() {
    let dir = TempDir::new("dry");
    let raw = dir.join("short.bin");
    fs::write(&raw, noise(20_000)).unwrap();
    let input = dir.join("input");
    fs::write(&input, b"x").unwrap();
    let out = veil(&[
        "split",
        &input,
        "-o",
        &dir.join(""),
        "--entropy",
        &raw,
        "--min-entropy",
        "7",
    ]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("failed or ran out"),
        "{}",
        stderr(&out)
    );
    assert!(files_in(dir.0.to_str().unwrap(), ".veil").is_empty());
}

#[test]
fn weak_source_and_misused_flags_are_refused() {
    let dir = TempDir::new("flags");
    let raw = dir.join("noise.bin");
    fs::write(&raw, noise(10_000)).unwrap();
    let input = dir.join("input");
    fs::write(&input, b"x").unwrap();
    let out = veil(&["split", &input, "--entropy", &raw, "--min-entropy", "2"]);
    assert!(
        stderr(&out).contains("too little min-entropy"),
        "{}",
        stderr(&out)
    );
    let out = veil(&["split", &input, "--seed", &raw]);
    assert_eq!(out.status.code(), Some(2));
    let out = veil(&["split", &input, "--entropy", &raw]);
    assert_eq!(out.status.code(), Some(2));
}

/// The 27 words `compose` prints, in order.
fn printed_words(stdout: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .skip_while(|l| !l.starts_with("your 27 words"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .flat_map(|l| l.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .filter(|t| t.chars().all(|c| c.is_ascii_lowercase()))
        .collect()
}

#[test]
fn composed_key_needs_shares_and_words() {
    let dir = TempDir::new("compose");
    let out = veil(&[
        "compose",
        "--words-off-screen",
        "-o",
        dir.0.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let words = printed_words(&out.stdout);
    assert_eq!(words.len(), 27, "{words:?}");
    let key = fs::read(&files_in(dir.0.to_str().unwrap(), ".key")[0]).unwrap();
    assert_eq!(key.len(), 32);
    let s = files_in(dir.0.to_str().unwrap(), ".veil");

    let out = veil_with_stdin(
        &["recover", &s[0], &s[2], &s[4], "-o", "-"],
        &words.join(" "),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, key);

    let other = TempDir::new("compose-other");
    let out = veil(&[
        "compose",
        "--words-off-screen",
        "-o",
        other.0.to_str().unwrap(),
    ]);
    let wrong = printed_words(&out.stdout).join(" ");
    let out = veil_with_stdin(&["recover", &s[1], &s[2], &s[3], "-o", "-"], &wrong);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("do not combine"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());

    let out = veil(&["combine", &s[0], &s[1], &s[2], "-o", "-"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("use veil recover"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn compose_protects_an_existing_key() {
    let dir = TempDir::new("compose-key");
    let key_path = dir.join("my.key");
    let key: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
    fs::write(&key_path, &key).unwrap();
    let shares = dir.join("shares");
    fs::create_dir(&shares).unwrap();
    let out = veil(&[
        "compose",
        "--words-off-screen",
        "--key",
        &key_path,
        "-o",
        &shares,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        files_in(&shares, ".key").is_empty(),
        "an existing key is never written back out"
    );

    let s = files_in(&shares, ".veil");
    let words = printed_words(&out.stdout).join(" ");
    let out = veil_with_stdin(&["recover", &s[3], &s[4], &s[0], "-o", "-"], &words);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, key);

    fs::write(&key_path, &key[..31]).unwrap();
    let out = veil(&[
        "compose",
        "--words-off-screen",
        "--key",
        &key_path,
        "-o",
        &shares,
    ]);
    assert!(
        stderr(&out).contains("exactly 32 bytes"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn forged_key_exists_only_once_recovered() {
    let dir = TempDir::new("forge");
    let out = veil(&["forge", "--words-off-screen", "-o", dir.0.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("never computed"), "{stdout}");
    assert!(stdout.contains("no keyboard attached"), "{stdout}");
    assert!(
        files_in(dir.0.to_str().unwrap(), ".key").is_empty(),
        "forge writes no key file"
    );
    let words = printed_words(&out.stdout).join(" ");
    let s = files_in(dir.0.to_str().unwrap(), ".veil");
    assert_eq!(s.len(), 5);

    let first = veil_with_stdin(&["recover", &s[0], &s[2], &s[4], "-o", "-"], &words);
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(first.stdout.len(), 32);
    let second = veil_with_stdin(&["recover", &s[1], &s[3], &s[4], "-o", "-"], &words);
    assert_eq!(
        second.stdout, first.stdout,
        "every 3 shares bring the same key into being"
    );

    let out = veil(&["combine", &s[0], &s[1], &s[2], "-o", "-"]);
    assert!(
        stderr(&out).contains("use veil recover"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn forge_can_skip_the_ripple() {
    let dir = TempDir::new("forge-quiet");
    let out = veil(&[
        "forge",
        "--words-off-screen",
        "--no-ripple",
        "-o",
        dir.0.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("no keyboard"));
    let out = veil(&["forge", "secret.txt"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn write_refuses_anything_but_a_keyboard() {
    let out = veil(&["write"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("needs a keyboard"),
        "{}",
        stderr(&out)
    );
    let out = veil(&["write", "secret.txt"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn words_never_land_in_a_file_unasked() {
    let dir = TempDir::new("words-off-screen");
    for command in ["compose", "forge"] {
        let out = veil(&[command, "-o", dir.0.to_str().unwrap()]);
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("--words-off-screen"),
            "{}",
            stderr(&out)
        );
        assert!(out.stdout.is_empty());
    }
    assert!(
        files_in(dir.0.to_str().unwrap(), "").is_empty(),
        "nothing is made when the words have nowhere safe to go"
    );
}
