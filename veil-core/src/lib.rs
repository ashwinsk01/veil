//! Veil core: split one small file into `n` shares so that any `k` of them rebuild it and any
//! `k - 1` reveal nothing at all, with tamper detection that rests on no computational assumption.
//!
//! The byte-level format is specified in `SPEC.md` at the repository root.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod compose;
mod entropy;
mod extract;
mod format;
mod gf256;
mod mac;
mod refresh;
mod share;

use core::fmt;
use zeroize::Zeroize;

pub use compose::{
    COMPOSE_MAGIC, COMPOSED_KEY_LEN, FACTOR_LEN, PAYLOAD_LEN, WORD_COUNT, compose, factor_to_words,
    is_composed, recover, word, words_to_factor,
};
pub use entropy::{APT_WINDOW, Conditioned, HealthTests, Mix, RawSource, STARTUP_SAMPLES};
pub use extract::{DICE_ROLLS, MAX_OUTPUT, RAW_BLOCK, SEED_LEN, Toeplitz, seed_from_dice};
pub use format::{
    HEADER_LEN, KEY_LEN, KEYCARD_MAGIC, KeycardView, MAGIC, MASK_MAGIC, SetId, ShareView, TAG_LEN,
    VERSION, check_params, keycard_len, mask_len, share_len,
};
pub use refresh::{HashKeys, apply, deal, keycard};
pub use share::{AuthFailures, combine, split, verify};

/// Largest file Veil holds, in bytes.
pub const MAX_FILE: usize = 10_240;

/// Size of the block that gets split: a 2-byte length, the file, then zero padding.
pub const SECRET_LEN: usize = 2 + MAX_FILE;

/// Most shares one split can produce.
pub const MAX_SHARES: usize = 16;

/// A source of uniformly random bytes. Every guarantee in this crate rests on it.
pub trait Entropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    FileTooLarge,
    BadParams,
    BadLength,
    BadMagic,
    UnsupportedVersion(u8),
    BadIndex,
    MixedSets,
    DuplicateShare(u8),
    NotEnoughShares { have: u8, need: u8 },
    TooManyShares,
    TamperDetected(AuthFailures),
    Corrupt,
    Entropy,
    EpochExhausted,
    WrongMask,
    SourceTooWeak,
    HealthTestFailed,
    BadWords,
    FactorsDontCombine,
    NotComposed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FileTooLarge => write!(f, "file is larger than {MAX_FILE} bytes"),
            Error::BadParams => write!(
                f,
                "threshold and share count must satisfy 2 <= k <= n <= {MAX_SHARES}"
            ),
            Error::BadLength => write!(f, "share has the wrong length"),
            Error::BadMagic => write!(f, "not the expected kind of veil file"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported share format version {v}"),
            Error::BadIndex => write!(f, "share index is out of range"),
            Error::MixedSets => write!(f, "shares come from different splits or epochs"),
            Error::DuplicateShare(x) => write!(f, "share {x} was supplied more than once"),
            Error::NotEnoughShares { have, need } => write!(f, "need {need} shares, got {have}"),
            Error::TooManyShares => write!(f, "more than {MAX_SHARES} shares supplied"),
            Error::TamperDetected(_) => {
                write!(f, "tamper detected: shares failed cross-verification")
            }
            Error::Corrupt => write!(f, "recovered block is malformed"),
            Error::Entropy => write!(f, "random number source failed or ran out"),
            Error::EpochExhausted => write!(f, "epoch counter is exhausted"),
            Error::WrongMask => write!(f, "mask was not made for this share and epoch"),
            Error::SourceTooWeak => write!(f, "source has too little min-entropy to extract from"),
            Error::HealthTestFailed => write!(
                f,
                "hardware source failed its health tests: it is stuck or has lost its entropy"
            ),
            Error::BadWords => write!(
                f,
                "the words are misspelled, missing, or not from the word list"
            ),
            Error::FactorsDontCombine => write!(f, "the shares and the words do not combine"),
            Error::NotComposed => write!(f, "these shares do not hold a composed key"),
        }
    }
}

/// The padded block that gets split. Zeroed when dropped.
pub struct Secret {
    buf: [u8; SECRET_LEN],
}

impl Secret {
    pub const fn new() -> Self {
        Self {
            buf: [0; SECRET_LEN],
        }
    }

    /// Replaces the contents with `file`, padded to the fixed block size.
    pub fn load(&mut self, file: &[u8]) -> Result<(), Error> {
        if file.len() > MAX_FILE {
            return Err(Error::FileTooLarge);
        }
        self.buf.zeroize();
        self.buf[..2].copy_from_slice(&(file.len() as u16).to_be_bytes());
        self.buf[2..2 + file.len()].copy_from_slice(file);
        Ok(())
    }

    /// The file held in the block, after checking its length and zero padding.
    pub fn file(&self) -> Result<&[u8], Error> {
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if len > MAX_FILE || self.buf[2 + len..].iter().any(|&b| b != 0) {
            return Err(Error::Corrupt);
        }
        Ok(&self.buf[2..2 + len])
    }

    pub(crate) fn bytes(&self) -> &[u8; SECRET_LEN] {
        &self.buf
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; SECRET_LEN] {
        &mut self.buf
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.buf.zeroize();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.zeroize();
    }
}
