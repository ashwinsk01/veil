//! Where the randomness comes from: the OS generator alone, or a hardware noise source that is
//! health-tested, run through the extractor, and XORed with the OS generator.

use std::fs::File;
use std::io::Read;
use veil_core::{
    APT_WINDOW, Conditioned, DICE_ROLLS, Entropy, Error, HealthTests, Mix, RAW_BLOCK, RawSource,
    SEED_LEN, Toeplitz,
};

/// Health test false alarm rate, as a power of two. SP 800-90B allows 2^-20 to 2^-40.
const ALARM_BITS: f64 = 30.0;

/// The operating system's random generator: a seeded computational generator.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(buf).map_err(|_| Error::Entropy)
    }
}

/// Raw noise read from a device, a pipe, or a capture file.
pub struct RawFile(File);

impl RawSource for RawFile {
    fn read_raw(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(buf).map_err(|_| Error::Entropy)
    }
}

pub enum Randomness {
    Os(OsEntropy),
    Hardware {
        mix: Mix<OsEntropy, Conditioned<RawFile>>,
        min_entropy: f64,
        dice_seed: bool,
    },
}

impl Randomness {
    /// Opens a hardware source that gives at least `min_entropy` bits per byte, and runs its
    /// start-up health test. Without a dice seed, the OS generator picks the extractor seed.
    pub fn hardware(
        path: &str,
        min_entropy: f64,
        seed: Option<[u8; SEED_LEN]>,
    ) -> Result<Self, String> {
        let dice_seed = seed.is_some();
        let seed = match seed {
            Some(seed) => seed,
            None => {
                let mut seed = [0; SEED_LEN];
                OsEntropy.fill(&mut seed).map_err(|e| e.to_string())?;
                seed
            }
        };
        let block_min_entropy = (min_entropy * RAW_BLOCK as f64).floor() as u32;
        let extractor = Toeplitz::new(&seed, block_min_entropy)
            .map_err(|e| format!("{e}: --min-entropy must be above 2.125 bits per byte"))?;
        let health = HealthTests::new(
            rct_cutoff(min_entropy, ALARM_BITS),
            apt_cutoff(min_entropy, ALARM_BITS),
        );
        let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
        let source = Conditioned::new(RawFile(file), health, extractor)
            .map_err(|e| format!("{path}: {e}"))?;
        Ok(Self::Hardware {
            mix: Mix(OsEntropy, source),
            min_entropy,
            dice_seed,
        })
    }

    /// One line saying what the randomness of the last operation rested on.
    pub fn summary(&self) -> String {
        match self {
            Self::Os(_) => "randomness: OS generator only, a computational assumption. \
                            --entropy with a hardware source removes it."
                .to_owned(),
            Self::Hardware {
                mix,
                min_entropy,
                dice_seed,
            } => {
                let blocks = mix.1.blocks_used().max(1);
                let bits = (mix.1.security_bits() as f64 - (blocks as f64).log2()).floor();
                let seed = if *dice_seed {
                    "the extractor seed came from dice."
                } else {
                    "the extractor seed came from the OS generator; a dice seed (veil seed) \
                     makes this hold with no computational assumption."
                };
                format!(
                    "randomness: hardware noise XOR the OS generator, {blocks} raw blocks. within \
                     2^-{bits} of uniform if the source gives at least {min_entropy} bits of \
                     min-entropy per byte. {seed}"
                )
            }
        }
    }
}

impl Entropy for Randomness {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::Os(os) => os.fill(buf),
            Self::Hardware { mix, .. } => mix.fill(buf),
        }
    }
}

/// Repetition count cutoff (SP 800-90B §4.4.1): 1 + ⌈alarm / H⌉.
fn rct_cutoff(min_entropy: f64, alarm_bits: f64) -> u32 {
    1 + (alarm_bits / min_entropy).ceil() as u32
}

/// Adaptive proportion cutoff (SP 800-90B §4.4.2): 1 + the smallest c with
/// P[Binomial(512, 2^-H) ≤ c] ≥ 1 − 2^-alarm.
fn apt_cutoff(min_entropy: f64, alarm_bits: f64) -> u32 {
    let (n, p) = (APT_WINDOW, 2f64.powf(-min_entropy));
    let target = 1.0 - 2f64.powf(-alarm_bits);
    let mut pmf = (1.0 - p).powi(n as i32);
    let mut cdf = pmf;
    let mut c = 0;
    while cdf < target && c < n {
        pmf *= (n - c) as f64 / (c + 1) as f64 * p / (1.0 - p);
        c += 1;
        cdf += pmf;
    }
    1 + c
}

/// Reads a seed written by `veil seed`: 160 hex digits, whitespace ignored.
pub fn read_seed(path: &str) -> Result<[u8; SEED_LEN], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() != 2 * SEED_LEN {
        return Err(format!(
            "{path}: a seed is {} hex digits, found {}",
            2 * SEED_LEN,
            digits.len()
        ));
    }
    let mut seed = [0; SEED_LEN];
    for (byte, pair) in seed.iter_mut().zip(digits.chunks(2)) {
        *byte = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(|| format!("{path}: not a hex seed"))?;
    }
    Ok(seed)
}

/// Parses typed die rolls: digits 1 to 6, with spaces, commas and newlines ignored.
pub fn rolls_from_text(text: &str) -> Result<[u8; DICE_ROLLS], String> {
    let mut rolls = Vec::with_capacity(DICE_ROLLS);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != ',') {
        match c.to_digit(10) {
            Some(d @ 1..=6) => rolls.push(d as u8),
            _ => return Err(format!("'{c}' is not a die roll: use the digits 1 to 6")),
        }
    }
    if rolls.len() != DICE_ROLLS {
        return Err(format!(
            "need exactly {DICE_ROLLS} rolls, got {}",
            rolls.len()
        ));
    }
    // A fair die lands the same way 10 times running in 272 rolls about once in 38,000 tries.
    if rolls.windows(10).any(|w| w.iter().all(|&r| r == w[0])) {
        return Err("the same face came up 10 times in a row: use real rolls of a fair die".into());
    }
    let mut out = [0; DICE_ROLLS];
    out.copy_from_slice(&rolls);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SP 800-90B, Table 2: adaptive proportion cutoffs for a 512-sample window at α = 2^-20.
    #[test]
    fn apt_cutoffs_match_the_nist_table() {
        for (h, expected) in [(1.0, 311), (2.0, 177), (4.0, 62), (8.0, 13)] {
            assert_eq!(apt_cutoff(h, 20.0), expected, "H={h}");
        }
    }

    #[test]
    fn rct_cutoffs_follow_the_formula() {
        assert_eq!(rct_cutoff(8.0, 20.0), 4);
        assert_eq!(rct_cutoff(7.5, 30.0), 5);
        assert_eq!(rct_cutoff(3.0, 30.0), 11);
    }

    #[test]
    fn rolls_are_validated() {
        let good: String = (0..DICE_ROLLS)
            .map(|i| char::from(b'1' + (i * 5 % 6) as u8))
            .collect();
        assert!(rolls_from_text(&good).is_ok());
        assert!(rolls_from_text(&good[1..]).is_err());
        assert!(rolls_from_text(&good.replacen('1', "7", 1)).is_err());
        let stuck = format!("{}{}", "4".repeat(10), &good[10..]);
        assert!(rolls_from_text(&stuck).is_err());
    }
}
