//! `veil`: split one small file into shares, check them, refresh them, and recombine them.

mod harden;
mod randomness;

use harden::Locked;
use randomness::{OsEntropy, Randomness, read_seed, rolls_from_text};
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use veil_core::{
    AuthFailures, COMPOSED_KEY_LEN, Entropy, Error, FACTOR_LEN, HashKeys, KeycardView, MAX_FILE,
    MAX_SHARES, PAYLOAD_LEN, Secret, SetId, ShareView, WORD_COUNT, check_params, keycard_len,
    mask_len, share_len,
};
use zeroize::Zeroize;

const USAGE: &str = "\
usage:
  veil split <file> [-k <threshold>] [-n <shares>] [-o <dir>] [randomness]
  veil combine <share>... -o <file | ->
  veil check <share>...
  veil refresh <every share> [-o <dir>] [randomness]
  veil keycard <share>... [-o <dir>]
  veil deal <every keycard> [-o <dir>] [randomness]
  veil apply <share> <mask> [-o <dir>]
  veil seed [-o <file>]
  veil compose [-k <threshold>] [-n <shares>] [-o <dir>] [--key <file>] [randomness]
  veil recover <share>... -o <file | ->

split    writes n share files; any k of them rebuild the file, fewer reveal nothing
combine  checks every share against every other, then rebuilds the file
check    checks shares against each other without rebuilding anything
refresh  moves a complete set to the next epoch without rebuilding the file;
         shares from different epochs never combine

refresh with the shares kept apart:
  1. each vault  veil keycard <its share>        send the keycard to the dealer
  2. dealer      veil deal <every keycard>       send each mask to its vault only
  3. each vault  veil apply <its share> <mask>   then destroy the old share and mask

randomness, for split, refresh and deal:
  --entropy <device or file>  raw hardware noise: health-tested, extracted, then XORed
                              with the OS generator. without it, the OS generator alone
  --min-entropy <bits>        min-entropy per raw byte that the source is known to give
  --seed <file>               extractor seed from veil seed. without it, the OS
                              generator picks one
seed     turns 272 rolls of a fair die, typed on stdin, into an extractor seed.
         the seed is public: it only has to come from real dice
compose  protects a 32-byte key with shares AND 27 memorized words. the shares, even all
         together, reveal nothing without the words. without --key, makes a new key
recover  rebuilds a composed key from enough shares plus your words

defaults: -k 3 -n 5 -o .    largest file: 10240 bytes";

enum Failure {
    Usage(String),
    Fatal(String),
}

type Result<T> = std::result::Result<T, Failure>;

fn usage(msg: impl Display) -> Failure {
    Failure::Usage(msg.to_string())
}

fn fatal(msg: impl Display) -> Failure {
    Failure::Fatal(msg.to_string())
}

fn main() -> ExitCode {
    if let Err(e) = harden::process() {
        eprintln!("veil: cannot harden process: {e}");
        return ExitCode::FAILURE;
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("split") => split(&args[1..]),
        Some("combine") => combine(&args[1..]),
        Some("check") => check(&args[1..]),
        Some("refresh") => refresh(&args[1..]),
        Some("keycard") => keycard(&args[1..]),
        Some("deal") => deal(&args[1..]),
        Some("apply") => apply(&args[1..]),
        Some("seed") => seed(&args[1..]),
        Some("compose") => compose(&args[1..]),
        Some("recover") => recover(&args[1..]),
        Some("help" | "-h" | "--help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(usage(format!("unknown command '{other}'"))),
        None => Err(usage("no command given")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(msg)) => {
            eprintln!("veil: {msg}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Fatal(msg)) => {
            eprintln!("veil: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Args {
    positional: Vec<String>,
    k: Option<u8>,
    n: Option<u8>,
    out: Option<String>,
    entropy: Option<String>,
    min_entropy: Option<String>,
    seed: Option<String>,
    key: Option<String>,
}

fn parse_args(args: &[String], flags: &[&str]) -> Result<Args> {
    let mut parsed = Args::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let flag = arg.as_str();
        if !flags.contains(&flag) {
            if flag.starts_with('-') && flag != "-" {
                return Err(usage(format!("unknown option '{flag}'")));
            }
            parsed.positional.push(arg.clone());
            continue;
        }
        let value = iter
            .next()
            .ok_or_else(|| usage(format!("{flag} needs a value")))?;
        let number = || {
            value
                .parse::<u8>()
                .map_err(|_| usage(format!("{flag} needs a number, got '{value}'")))
        };
        match flag {
            "-k" => parsed.k = Some(number()?),
            "-n" => parsed.n = Some(number()?),
            "--entropy" => parsed.entropy = Some(value.clone()),
            "--min-entropy" => parsed.min_entropy = Some(value.clone()),
            "--seed" => parsed.seed = Some(value.clone()),
            "--key" => parsed.key = Some(value.clone()),
            _ => parsed.out = Some(value.clone()),
        }
    }
    Ok(parsed)
}

fn split(args: &[String]) -> Result<()> {
    let args = parse_args(
        args,
        &["-k", "-n", "-o", "--entropy", "--min-entropy", "--seed"],
    )?;
    let [path] = args.positional.as_slice() else {
        return Err(usage("split takes exactly one file"));
    };
    let (k, n) = (args.k.unwrap_or(3), args.n.unwrap_or(5));
    check_params(k, n).map_err(usage)?;
    let dir = out_dir(&args);
    let mut rng = randomness(&args)?;

    let mut secret = Locked::new(Box::new(Secret::new())).map_err(cannot_lock)?;
    {
        let mut buf =
            Locked::new(vec![0u8; MAX_FILE + 1].into_boxed_slice()).map_err(cannot_lock)?;
        let len = read_capped(path, &mut buf)?;
        if len > MAX_FILE {
            return Err(fatal(format!("{path}: {}", Error::FileTooLarge)));
        }
        secret.load(&buf[..len]).map_err(fatal)?;
    }

    write_split(&secret, k, n, &mut rng, &dir)?;
    println!("any {k} of these {n} shares rebuild the file; fewer reveal nothing about it.");
    println!("{path} itself was left untouched.");
    println!("{}", rng.summary());
    Ok(())
}

fn combine(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o"])?;
    let out = args
        .out
        .ok_or_else(|| usage("combine needs -o <file>, or -o - for stdout"))?;
    let files = load(&args.positional, share_len(MAX_SHARES as u8))?;
    let views = parse_views(&files)?;
    let secret = rebuild(&views)?;
    let file = secret.file().map_err(fatal)?;
    if veil_core::is_composed(file) {
        return Err(fatal(
            "these shares hold a composed key: use veil recover, which also asks for your words",
        ));
    }
    write_output(&out, file)?;
    eprintln!("set id {}", hex(&views[0].set_id()));
    eprintln!("check that it matches the set id recorded at split time.");
    Ok(())
}

fn check(args: &[String]) -> Result<()> {
    let args = parse_args(args, &[])?;
    let files = load(&args.positional, share_len(MAX_SHARES as u8))?;
    let views = parse_views(&files)?;
    for (file, view) in files.iter().zip(&views) {
        println!(
            "{}: share {} of {}, threshold {}, epoch {}, set id {}",
            file.path,
            view.index(),
            view.total(),
            view.threshold(),
            view.epoch(),
            hex(&view.set_id())
        );
    }
    if views.len() < 2 {
        println!("give at least 2 shares to cross-check them.");
        return Ok(());
    }
    match veil_core::verify(&views) {
        Ok(()) => {
            println!(
                "all {} cross-checks passed. nothing was rebuilt.",
                views.len() * (views.len() - 1)
            );
            Ok(())
        }
        Err(e) => {
            if let Error::TamperDetected(failures) = &e {
                report(&views, failures);
            }
            Err(fatal(e))
        }
    }
}

fn refresh(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o", "--entropy", "--min-entropy", "--seed"])?;
    let dir = out_dir(&args);
    let mut rng = randomness(&args)?;
    let mut files = load(&args.positional, share_len(MAX_SHARES as u8))?;
    let (keys, indices) = {
        let views = parse_views(&files)?;
        let keys = HashKeys::collect(&views).map_err(|e| {
            if let Error::TamperDetected(failures) = &e {
                report(&views, failures);
            }
            fatal(e)
        })?;
        (keys, views.iter().map(ShareView::index).collect::<Vec<_>>())
    };

    let mut masks = (0..files.len())
        .map(|_| Locked::new(vec![0u8; mask_len(files.len() as u8)].into_boxed_slice()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(cannot_lock)?;
    let mut refs: Vec<&mut [u8]> = masks.iter_mut().map(|m| &mut m[..]).collect();
    veil_core::deal(&keys, &mut rng, &mut refs).map_err(fatal)?;
    for (file, &x) in files.iter_mut().zip(&indices) {
        veil_core::apply(file.bytes_mut(), &masks[x as usize - 1]).map_err(fatal)?;
    }
    drop(masks);

    // The new set must pass every cross-check before anything is written.
    let views = parse_views(&files)?;
    veil_core::verify(&views).map_err(|e| {
        fatal(format!(
            "refreshed shares failed verification, nothing written: {e}"
        ))
    })?;
    let (epoch, total, k) = (views[0].epoch(), views[0].total(), views[0].threshold());
    let mut order: Vec<usize> = (0..files.len()).collect();
    order.sort_by_key(|&i| indices[i]);
    for i in order {
        let file = dir.join(file_name(
            &views[i].set_id(),
            epoch,
            indices[i],
            total,
            "veil",
        ));
        write_new(&file, files[i].bytes())?;
        println!("wrote {}", file.display());
    }
    println!("all {total} shares moved to epoch {epoch}. the file was never rebuilt.");
    println!("{}", rng.summary());
    println!(
        "now destroy every epoch {} share: until they are gone, any {k} of them still rebuild the file.",
        epoch - 1
    );
    Ok(())
}

fn keycard(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o"])?;
    let dir = out_dir(&args);
    let files = load(&args.positional, share_len(MAX_SHARES as u8))?;
    for view in parse_views(&files)? {
        let mut card = Locked::new(vec![0u8; keycard_len(view.total())].into_boxed_slice())
            .map_err(cannot_lock)?;
        veil_core::keycard(&view, &mut card).map_err(fatal)?;
        let (id, epoch, x, n) = (view.set_id(), view.epoch(), view.index(), view.total());
        let file = dir.join(file_name(&id, epoch, x, n, "veilkey"));
        write_new(&file, &card)?;
        println!("wrote {}", file.display());
    }
    println!("send keycards only to the dealer, then destroy them.");
    println!(
        "they hold no share data, but a keycard plus another share is enough to forge that share's seal."
    );
    Ok(())
}

fn deal(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o", "--entropy", "--min-entropy", "--seed"])?;
    let dir = out_dir(&args);
    let mut rng = randomness(&args)?;
    let files = load(&args.positional, keycard_len(MAX_SHARES as u8))?;
    let cards = files
        .iter()
        .map(|f| KeycardView::parse(f.bytes()).map_err(|e| fatal(format!("{}: {e}", f.path))))
        .collect::<Result<Vec<_>>>()?;
    let keys = HashKeys::from_keycards(&cards).map_err(fatal)?;
    let (id, epoch, n) = (cards[0].set_id(), cards[0].epoch(), cards[0].total());

    let mut masks = (0..n)
        .map(|_| Locked::new(vec![0u8; mask_len(n)].into_boxed_slice()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(cannot_lock)?;
    let mut refs: Vec<&mut [u8]> = masks.iter_mut().map(|m| &mut m[..]).collect();
    veil_core::deal(&keys, &mut rng, &mut refs).map_err(fatal)?;
    for (i, mask) in masks.iter().enumerate() {
        let file = dir.join(file_name(&id, epoch, i as u8 + 1, n, "veilmask"));
        write_new(&file, mask)?;
        println!("wrote {}", file.display());
    }
    println!(
        "send each mask only to the vault holding that share: a mask moves its share between epochs."
    );
    println!("destroy the keycards now, and each mask once it has been applied.");
    println!("{}", rng.summary());
    Ok(())
}

fn apply(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o"])?;
    let dir = out_dir(&args);
    let [share_path, mask_path] = args.positional.as_slice() else {
        return Err(usage("apply takes a share and its mask"));
    };
    let mut files = load(&args.positional, mask_len(MAX_SHARES as u8))?;
    ShareView::parse(files[0].bytes()).map_err(|e| fatal(format!("{share_path}: {e}")))?;
    let (share, mask) = files.split_at_mut(1);
    veil_core::apply(share[0].bytes_mut(), mask[0].bytes())
        .map_err(|e| fatal(format!("{mask_path}: {e}")))?;

    let view = ShareView::parse(share[0].bytes()).map_err(fatal)?;
    let (id, epoch, x, n) = (view.set_id(), view.epoch(), view.index(), view.total());
    let file = dir.join(file_name(&id, epoch, x, n, "veil"));
    write_new(&file, share[0].bytes())?;
    println!("wrote {}", file.display());
    println!("now destroy {share_path} and {mask_path}.");
    if view.threshold() > 2 {
        println!(
            "to confirm it, cross-check it against one other vault's new share with veil check."
        );
    }
    Ok(())
}

fn seed(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o"])?;
    let out = args.out.unwrap_or_else(|| "veil-seed.txt".to_owned());
    eprintln!(
        "roll a fair six-sided die {} times and type each result (1 to 6). spaces and \
         newlines are ignored. finish with ctrl-d.",
        veil_core::DICE_ROLLS
    );
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| fatal(format!("stdin: {e}")))?;
    let rolls = rolls_from_text(&text).map_err(fatal)?;
    let seed = veil_core::seed_from_dice(&rolls).map_err(fatal)?;
    write_new(Path::new(&out), format!("{}\n", hex(&seed)).as_bytes())?;
    println!("wrote {out}");
    println!("the seed is public: it can be printed, shared or reused. it only has to come from");
    println!("real dice, rolled without knowing anything about the noise source.");
    Ok(())
}

fn compose(args: &[String]) -> Result<()> {
    let args = parse_args(
        args,
        &[
            "-k",
            "-n",
            "-o",
            "--key",
            "--entropy",
            "--min-entropy",
            "--seed",
        ],
    )?;
    if !args.positional.is_empty() {
        return Err(usage(
            "compose takes no file; use --key to protect an existing key",
        ));
    }
    let (k, n) = (args.k.unwrap_or(3), args.n.unwrap_or(5));
    check_params(k, n).map_err(usage)?;
    let dir = out_dir(&args);
    let mut rng = randomness(&args)?;

    let mut key = Locked::new(Box::new([0u8; COMPOSED_KEY_LEN])).map_err(cannot_lock)?;
    match args.key.as_deref() {
        Some(path) => {
            let mut buf = Locked::new(vec![0u8; COMPOSED_KEY_LEN + 1].into_boxed_slice())
                .map_err(cannot_lock)?;
            if read_capped(path, &mut buf)? != COMPOSED_KEY_LEN {
                return Err(fatal(format!(
                    "{path}: a key must be exactly {COMPOSED_KEY_LEN} bytes"
                )));
            }
            key.copy_from_slice(&buf[..COMPOSED_KEY_LEN]);
        }
        None => rng.fill(&mut key[..]).map_err(fatal)?,
    }
    let mut payload = Locked::new(Box::new([0u8; PAYLOAD_LEN])).map_err(cannot_lock)?;
    let mut words = Locked::new(Box::new([0u8; FACTOR_LEN])).map_err(cannot_lock)?;
    veil_core::compose(&key, &mut rng, &mut payload, &mut words, None).map_err(fatal)?;

    let mut secret = Locked::new(Box::new(Secret::new())).map_err(cannot_lock)?;
    secret.load(&payload[..]).map_err(fatal)?;
    let set_id = write_split(&secret, k, n, &mut rng, &dir)?;
    if args.key.is_none() {
        let file = dir.join(format!("veil-{}-master.key", hex(&set_id[..4])));
        write_new(&file, &key[..])?;
        println!(
            "wrote {}: the key itself. use it, then delete this copy.",
            file.display()
        );
    }
    println!();
    println!("your {WORD_COUNT} words, the second factor:");
    print_words(&words);
    println!("without these words the shares are useless, to an attacker and to you. memorize");
    println!(
        "them, or write them down and keep them apart from every share. veil never stores them."
    );
    println!("{}", rng.summary());
    Ok(())
}

fn recover(args: &[String]) -> Result<()> {
    let args = parse_args(args, &["-o"])?;
    let out = args
        .out
        .ok_or_else(|| usage("recover needs -o <file>, or -o - for stdout"))?;
    let files = load(&args.positional, share_len(MAX_SHARES as u8))?;
    let views = parse_views(&files)?;
    let secret = rebuild(&views)?;
    let payload = secret.file().map_err(fatal)?;
    if !veil_core::is_composed(payload) {
        return Err(fatal(
            "these shares hold a plain file, not a composed key: use veil combine",
        ));
    }
    eprintln!("type your {WORD_COUNT} words (they will not be shown), then press enter:");
    let text = harden::read_secret().map_err(|e| fatal(format!("stdin: {e}")))?;
    let factor = Locked::new(Box::new(veil_core::words_to_factor(&text).map_err(fatal)?))
        .map_err(cannot_lock)?;
    let mut key = Locked::new(Box::new([0u8; COMPOSED_KEY_LEN])).map_err(cannot_lock)?;
    veil_core::recover(payload, &factor, None, &mut key).map_err(fatal)?;
    write_output(&out, &key[..])?;
    eprintln!("set id {}", hex(&views[0].set_id()));
    Ok(())
}

/// Splits `secret` k-of-n into new share files in `dir` and returns the set id.
fn write_split(secret: &Secret, k: u8, n: u8, rng: &mut Randomness, dir: &Path) -> Result<SetId> {
    let mut shares = (0..n)
        .map(|_| Locked::new(vec![0u8; share_len(n)].into_boxed_slice()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(cannot_lock)?;
    let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(|s| &mut s[..]).collect();
    let set_id = veil_core::split(secret, k, n, rng, &mut refs).map_err(fatal)?;
    for (i, share) in shares.iter().enumerate() {
        let file = dir.join(file_name(&set_id, 0, i as u8 + 1, n, "veil"));
        write_new(&file, share)?;
        println!("wrote {}", file.display());
    }
    println!("set id {}", hex(&set_id));
    println!("record the set id somewhere separate from the shares.");
    Ok(set_id)
}

/// Cross-verifies `views` and rebuilds what they hold, reporting any share that fails.
fn rebuild(views: &[ShareView<'_>]) -> Result<Locked<Secret>> {
    let mut secret = Locked::new(Box::new(Secret::new())).map_err(cannot_lock)?;
    veil_core::combine(views, &mut secret).map_err(|e| {
        if let Error::TamperDetected(failures) = &e {
            report(views, failures);
        }
        fatal(e)
    })?;
    Ok(secret)
}

/// Writes rebuilt plaintext to a new owner-only file, or to stdout for "-".
fn write_output(out: &str, bytes: &[u8]) -> Result<()> {
    if out == "-" {
        // Write straight to the descriptor so the plaintext never sits in a stdout buffer.
        let mut stdout = File::from(io::stdout().as_fd().try_clone_to_owned().map_err(fatal)?);
        stdout
            .write_all(bytes)
            .map_err(|e| fatal(format!("stdout: {e}")))
    } else {
        write_new(Path::new(out), bytes)?;
        eprintln!("wrote {out} ({} bytes)", bytes.len());
        Ok(())
    }
}

/// Prints a factor as numbered words, three per line.
fn print_words(factor: &[u8; FACTOR_LEN]) {
    let mut indices = veil_core::factor_to_words(factor);
    for (row, chunk) in indices.chunks(3).enumerate() {
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(i, &w)| format!("{:>2} {:<9}", 3 * row + i + 1, veil_core::word(w)))
            .collect();
        println!("  {}", line.join("  "));
    }
    indices.zeroize();
}

/// Picks the randomness the flags ask for. A hardware source runs its start-up test here, before
/// any secret is touched.
fn randomness(args: &Args) -> Result<Randomness> {
    let Some(path) = args.entropy.as_deref() else {
        if args.min_entropy.is_some() || args.seed.is_some() {
            return Err(usage("--min-entropy and --seed only apply with --entropy"));
        }
        return Ok(Randomness::Os(OsEntropy));
    };
    let text = args
        .min_entropy
        .as_deref()
        .ok_or_else(|| usage("--entropy needs --min-entropy <bits per byte>"))?;
    let min_entropy = text
        .parse::<f64>()
        .ok()
        .filter(|h| *h > 0.0 && *h <= 8.0)
        .ok_or_else(|| {
            usage(format!(
                "--min-entropy needs a number from 0 to 8, got '{text}'"
            ))
        })?;
    let seed = args
        .seed
        .as_deref()
        .map(read_seed)
        .transpose()
        .map_err(fatal)?;
    Randomness::hardware(path, min_entropy, seed).map_err(fatal)
}

/// A file read into pinned memory.
struct Loaded {
    path: String,
    buf: Locked<[u8]>,
    len: usize,
}

impl Loaded {
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

/// Reads every file in `paths`, refusing any longer than `largest` bytes.
fn load(paths: &[String], largest: usize) -> Result<Vec<Loaded>> {
    if paths.is_empty() {
        return Err(usage("no files given"));
    }
    paths
        .iter()
        .map(|path| {
            let mut buf =
                Locked::new(vec![0u8; largest + 1].into_boxed_slice()).map_err(cannot_lock)?;
            let len = read_capped(path, &mut buf)?;
            if len > largest {
                return Err(fatal(format!("{path}: {}", Error::BadLength)));
            }
            Ok(Loaded {
                path: path.clone(),
                buf,
                len,
            })
        })
        .collect()
}

fn parse_views(files: &[Loaded]) -> Result<Vec<ShareView<'_>>> {
    files
        .iter()
        .map(|f| ShareView::parse(f.bytes()).map_err(|e| fatal(format!("{}: {e}", f.path))))
        .collect()
}

fn report(views: &[ShareView<'_>], failures: &AuthFailures) {
    for view in views {
        let rejections = failures.rejections(view.index());
        if rejections > 0 {
            eprintln!(
                "  share {} was rejected by {rejections} of {} other shares",
                view.index(),
                views.len() - 1
            );
        }
    }
}

/// Reads up to `buf.len()` bytes; a result equal to `buf.len()` means the file may be longer.
fn read_capped(path: &str, buf: &mut [u8]) -> Result<usize> {
    let mut file = File::open(path).map_err(|e| fatal(format!("{path}: {e}")))?;
    let mut len = 0;
    while len < buf.len() {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(fatal(format!("{path}: {e}"))),
        }
    }
    Ok(len)
}

/// Creates `path` readable only by its owner, refusing to overwrite anything, and syncs it to disk.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let context = |e: io::Error| fatal(format!("{}: {e}", path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(context)?;
    file.write_all(bytes).map_err(context)?;
    file.sync_all().map_err(context)
}

/// File name for a share, keycard or mask: set id prefix, epoch, then which share of how many.
fn file_name(set_id: &SetId, epoch: u32, x: u8, n: u8, extension: &str) -> String {
    format!("veil-{}-e{epoch}-{x}of{n}.{extension}", hex(&set_id[..4]))
}

fn out_dir(args: &Args) -> PathBuf {
    PathBuf::from(args.out.as_deref().unwrap_or("."))
}

fn cannot_lock(e: io::Error) -> Failure {
    fatal(format!("cannot pin memory in RAM: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
