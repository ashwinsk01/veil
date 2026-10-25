//! Composition: a 32-byte key that opens only when the shares AND a memorized factor come together.
//!
//! The key and a 4-byte check pad form C (36 bytes), and C = X_shares ⊕ X_words. Each part is
//! uniformly random on its own, so the shares (all of them together) or the words alone carry no
//! information about the key. There is one check, at the very end: the first 4 bytes of
//! POLYVAL_h(key) ⊕ pad, with h held in the shares and the pad inside C, so the check value reveals
//! nothing either. Every wrong factor produces the same failure.
//!
//! The word list is the BIP-39 English list (CC0, via the rust-bip39 crate), chosen for
//! memorability: every word is identified by its first four letters.

use crate::{Entropy, Error, mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of the key a composition protects.
pub const COMPOSED_KEY_LEN: usize = 32;

/// Length of each factor: the key plus the check pad.
pub const FACTOR_LEN: usize = COMPOSED_KEY_LEN + CHECK_LEN;

/// Words that encode a factor: 288 bits plus a 9-bit checksum, 11 bits per word.
pub const WORD_COUNT: usize = 27;

/// Length of the payload the shares hold.
pub const PAYLOAD_LEN: usize = 62;

pub const COMPOSE_MAGIC: [u8; 4] = *b"VCMP";

const COMPOSE_VERSION: u8 = 1;
const CHECK_LEN: usize = 4;
const HASH_KEY_LEN: usize = 16;
/// Factors the payload needs besides the shares. Bit 1 is reserved for a device (PUF) factor.
const FACTOR_WORDS: u8 = 1;

const SHARES_PART: core::ops::Range<usize> = 6..6 + FACTOR_LEN;
const HASH_KEY: core::ops::Range<usize> = 42..42 + HASH_KEY_LEN;
const CHECK: core::ops::Range<usize> = 58..58 + CHECK_LEN;

static WORDLIST: &str = include_str!("words.txt");

/// Splits `key` into a payload for the shares and a factor for the words. Fills both.
pub fn compose<E: Entropy + ?Sized>(
    key: &[u8; COMPOSED_KEY_LEN],
    rng: &mut E,
    payload: &mut [u8; PAYLOAD_LEN],
    words: &mut [u8; FACTOR_LEN],
) -> Result<(), Error> {
    let mut pad = Zeroizing::new([0u8; CHECK_LEN]);
    let mut hash_key = [0u8; HASH_KEY_LEN];
    rng.fill(&mut pad[..])?;
    rng.fill(&mut hash_key)?;
    rng.fill(words)?;

    payload[..4].copy_from_slice(&COMPOSE_MAGIC);
    payload[4] = COMPOSE_VERSION;
    payload[5] = FACTOR_WORDS;
    let shares_part = &mut payload[SHARES_PART];
    for (i, byte) in shares_part.iter_mut().enumerate() {
        let c = if i < COMPOSED_KEY_LEN {
            key[i]
        } else {
            pad[i - COMPOSED_KEY_LEN]
        };
        *byte = c ^ words[i];
    }
    payload[HASH_KEY].copy_from_slice(&hash_key);
    payload[CHECK].copy_from_slice(&check(&hash_key, key, &pad[..]));
    Ok(())
}

/// Whether recovered share data holds a composition rather than a plain file.
pub fn is_composed(payload: &[u8]) -> bool {
    payload.len() == PAYLOAD_LEN && payload[..4] == COMPOSE_MAGIC
}

/// Rebuilds the key from the shares' payload and the words' factor, with one joint check.
pub fn recover(
    payload: &[u8],
    words: &[u8; FACTOR_LEN],
    key: &mut [u8; COMPOSED_KEY_LEN],
) -> Result<(), Error> {
    if !is_composed(payload) {
        return Err(Error::NotComposed);
    }
    if payload[4] != COMPOSE_VERSION || payload[5] != FACTOR_WORDS {
        return Err(Error::UnsupportedVersion(payload[4]));
    }
    let mut c = Zeroizing::new([0u8; FACTOR_LEN]);
    for ((c, s), w) in c.iter_mut().zip(&payload[SHARES_PART]).zip(words) {
        *c = s ^ w;
    }
    let (candidate, pad) = c.split_at(COMPOSED_KEY_LEN);
    let mut hash_key = [0u8; HASH_KEY_LEN];
    hash_key.copy_from_slice(&payload[HASH_KEY]);
    if !bool::from(check(&hash_key, candidate, pad)[..].ct_eq(&payload[CHECK])) {
        return Err(Error::FactorsDontCombine);
    }
    key.copy_from_slice(candidate);
    Ok(())
}

/// The joint check: the first 4 bytes of POLYVAL_h(key ‖ length) ⊕ pad.
fn check(hash_key: &[u8; HASH_KEY_LEN], key: &[u8], pad: &[u8]) -> [u8; CHECK_LEN] {
    let mut mac_key = Zeroizing::new([0u8; 2 * HASH_KEY_LEN]);
    mac_key[..HASH_KEY_LEN].copy_from_slice(hash_key);
    mac_key[HASH_KEY_LEN..HASH_KEY_LEN + CHECK_LEN].copy_from_slice(pad);
    let tag = Zeroizing::new(mac::tag(&mac_key[..], key));
    [tag[0], tag[1], tag[2], tag[3]]
}

/// Encodes a factor as word-list indices: its bits most significant first, then the top 9 bits of
/// its CRC-16, 11 bits per word.
pub fn factor_to_words(factor: &[u8; FACTOR_LEN]) -> [u16; WORD_COUNT] {
    let mut bits = Zeroizing::new([0u8; FACTOR_LEN + 2]);
    bits[..FACTOR_LEN].copy_from_slice(factor);
    bits[FACTOR_LEN..].copy_from_slice(&crc16(factor).to_be_bytes());
    core::array::from_fn(|w| (0..11).fold(0u16, |acc, b| acc << 1 | bit(&bits[..], 11 * w + b)))
}

/// The word at `index` in the list.
pub fn word(index: u16) -> &'static str {
    WORDLIST.lines().nth(index as usize).unwrap_or_default()
}

/// Decodes typed words back into a factor. Case is ignored, and each word may be shortened to its
/// first four letters. Typos are caught by the checksum, which says nothing about the key.
pub fn words_to_factor(text: &str) -> Result<[u8; FACTOR_LEN], Error> {
    let mut indices = [0u16; WORD_COUNT];
    let mut count = 0;
    for token in text.split_whitespace() {
        if count == WORD_COUNT {
            return Err(Error::BadWords);
        }
        indices[count] = lookup(token).ok_or(Error::BadWords)?;
        count += 1;
    }
    if count != WORD_COUNT {
        return Err(Error::BadWords);
    }
    let mut bits = Zeroizing::new([0u8; FACTOR_LEN + 2]);
    for (w, &index) in indices.iter().enumerate() {
        for b in 0..11 {
            let at = 11 * w + b;
            bits[at / 8] |= ((index >> (10 - b) & 1) as u8) << (7 - at % 8);
        }
    }
    let mut factor = [0u8; FACTOR_LEN];
    factor.copy_from_slice(&bits[..FACTOR_LEN]);
    let checksum = u16::from_be_bytes([bits[FACTOR_LEN], bits[FACTOR_LEN + 1]]);
    if checksum >> 7 != crc16(&factor) >> 7 {
        return Err(Error::BadWords);
    }
    Ok(factor)
}

fn lookup(token: &str) -> Option<u16> {
    let mut by_prefix = None;
    for (i, candidate) in WORDLIST.lines().enumerate() {
        if candidate.eq_ignore_ascii_case(token) {
            return Some(i as u16);
        }
        let prefix_ok = token.len() >= 4
            && candidate.len() > token.len()
            && candidate.as_bytes()[..token.len()].eq_ignore_ascii_case(token.as_bytes());
        if prefix_ok {
            by_prefix = Some(i as u16);
        }
    }
    by_prefix
}

fn bit(bytes: &[u8], at: usize) -> u16 {
    (bytes[at / 8] >> (7 - at % 8) & 1) as u16
}

/// CRC-16/CCITT-FALSE. Only for catching typos.
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc << 1 ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, string::String, vec::Vec};

    struct TestRng(u64);

    impl Entropy for TestRng {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            for byte in buf {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *byte = (z ^ (z >> 31)) as u8;
            }
            Ok(())
        }
    }

    fn composed(seed: u64) -> ([u8; 32], [u8; PAYLOAD_LEN], [u8; FACTOR_LEN]) {
        let mut rng = TestRng(seed);
        let mut key = [0u8; 32];
        rng.fill(&mut key).unwrap();
        let (mut payload, mut words) = ([0u8; PAYLOAD_LEN], [0u8; FACTOR_LEN]);
        compose(&key, &mut rng, &mut payload, &mut words).unwrap();
        (key, payload, words)
    }

    fn typed(words: &[u8; FACTOR_LEN]) -> String {
        let list = factor_to_words(words).map(word);
        list.join(" ")
    }

    #[test]
    fn shares_and_words_together_rebuild_the_key() {
        let (key, payload, words) = composed(1);
        let factor = words_to_factor(&typed(&words)).unwrap();
        let mut out = [0u8; 32];
        recover(&payload, &factor, &mut out).unwrap();
        assert_eq!(out, key);
    }

    /// Whatever the shares hold, every possible key fits them: for any key there are words that
    /// open the payload to exactly that key. So the shares, even all of them together, say nothing
    /// about which key it is.
    #[test]
    fn payload_fits_every_key() {
        let (_, payload, _) = composed(2);
        let mut hash_key = [0u8; HASH_KEY_LEN];
        hash_key.copy_from_slice(&payload[HASH_KEY]);
        for seed in 0..20 {
            let mut other = [0u8; 32];
            TestRng(1000 + seed).fill(&mut other).unwrap();
            let unpadded = check(&hash_key, &other, &[0; CHECK_LEN]);
            let mut forced = [0u8; FACTOR_LEN];
            for i in 0..FACTOR_LEN {
                let c = if i < 32 {
                    other[i]
                } else {
                    payload[CHECK][i - 32] ^ unpadded[i - 32]
                };
                forced[i] = payload[SHARES_PART][i] ^ c;
            }
            let mut out = [0u8; 32];
            recover(&payload, &forced, &mut out).unwrap();
            assert_eq!(out, other);
        }
    }

    #[test]
    fn wrong_words_and_wrong_shares_fail_the_same_way() {
        let (_, payload, words) = composed(3);
        let (_, other_payload, other_words) = composed(4);
        let mut out = [0u8; 32];
        assert_eq!(
            recover(&payload, &other_words, &mut out),
            Err(Error::FactorsDontCombine)
        );
        assert_eq!(
            recover(&other_payload, &words, &mut out),
            Err(Error::FactorsDontCombine)
        );
        assert_eq!(out, [0u8; 32], "a failed recovery writes nothing");
    }

    #[test]
    fn words_round_trip() {
        for seed in 0..50 {
            let (_, _, words) = composed(100 + seed);
            assert_eq!(words_to_factor(&typed(&words)).unwrap(), words);
        }
    }

    #[test]
    fn short_and_uppercase_words_are_accepted() {
        let (_, _, words) = composed(5);
        let shortened: Vec<String> = factor_to_words(&words)
            .map(word)
            .iter()
            .map(|w| w.get(..4).unwrap_or(w).to_uppercase())
            .collect();
        assert_eq!(words_to_factor(&shortened.join("  ")).unwrap(), words);
    }

    /// Swapping any one word for a different valid word must never open the key: the checksum
    /// usually catches it, and the joint check catches the rest.
    #[test]
    fn a_single_wrong_word_never_opens_the_key() {
        let (_, payload, words) = composed(6);
        let indices = factor_to_words(&words);
        let mut caught_by_checksum = 0;
        for position in 0..WORD_COUNT {
            for replacement in [7u16, 500, 1999] {
                let mut swapped = indices;
                swapped[position] = (indices[position] + replacement) % 2048;
                let text = swapped.map(word).join(" ");
                match words_to_factor(&text) {
                    Err(Error::BadWords) => caught_by_checksum += 1,
                    Ok(factor) => {
                        let mut out = [0u8; 32];
                        let result = recover(&payload, &factor, &mut out);
                        assert_eq!(result, Err(Error::FactorsDontCombine));
                    }
                    Err(other) => panic!("unexpected {other:?}"),
                }
            }
        }
        assert!(
            caught_by_checksum >= 75,
            "checksum caught only {caught_by_checksum} of 81"
        );
    }

    #[test]
    fn malformed_word_lists_are_refused() {
        let (_, _, words) = composed(7);
        let good = typed(&words);
        let missing: Vec<&str> = good.split(' ').skip(1).collect();
        assert_eq!(words_to_factor(&missing.join(" ")), Err(Error::BadWords));
        assert_eq!(
            words_to_factor(&format!("{good} abandon")),
            Err(Error::BadWords)
        );
        assert_eq!(
            words_to_factor(&good.replacen(' ', " notaword ", 1)),
            Err(Error::BadWords)
        );
    }

    #[test]
    fn crc16_check_value() {
        assert_eq!(crc16(b"123456789"), 0x29b1);
    }

    #[test]
    fn plain_files_are_not_compositions() {
        let mut out = [0u8; 32];
        assert_eq!(
            recover(b"just a file", &[0; FACTOR_LEN], &mut out),
            Err(Error::NotComposed)
        );
    }
}
