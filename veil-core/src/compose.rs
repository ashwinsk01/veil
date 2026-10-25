//! Composition: a 32-byte key that opens only when the shares AND a memorized factor come together,
//! and optionally a device too.
//!
//! The key and a 4-byte check pad form C (36 bytes), and C = X_shares ⊕ X_words, or
//! X_shares ⊕ X_words ⊕ X_device with a device factor from the fuzzy extractor. Each part is
//! uniformly random on its own, so any factor missing leaves no information about the key. There is one check, at the very end: the first 4 bytes of
//! POLYVAL_h(key) ⊕ pad, with h held in the shares and the pad inside C, so the check value reveals
//! nothing either. Every wrong factor produces the same failure. How the words spell their factor
//! is in [`crate::words`].

use crate::{Entropy, Error, mac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of the key a composition protects.
pub const COMPOSED_KEY_LEN: usize = 32;

/// Length of each factor: the key plus the check pad.
pub const FACTOR_LEN: usize = COMPOSED_KEY_LEN + CHECK_LEN;

/// Length of the payload the shares hold.
pub const PAYLOAD_LEN: usize = 62;

pub const COMPOSE_MAGIC: [u8; 4] = *b"VCMP";

const COMPOSE_VERSION: u8 = 1;
const CHECK_LEN: usize = 4;
const HASH_KEY_LEN: usize = 16;
/// Factors the payload needs besides the shares.
const FACTOR_WORDS: u8 = 1;
const FACTOR_DEVICE: u8 = 2;

const SHARES_PART: core::ops::Range<usize> = 6..6 + FACTOR_LEN;
const HASH_KEY: core::ops::Range<usize> = 42..42 + HASH_KEY_LEN;
const CHECK: core::ops::Range<usize> = 58..58 + CHECK_LEN;

/// Splits `key` into a payload for the shares and a random factor for the words, filling both.
/// With a device factor, such as one from [`crate::fuzzy::enroll`], the key needs that device too.
pub fn compose<E: Entropy + ?Sized>(
    key: &[u8; COMPOSED_KEY_LEN],
    rng: &mut E,
    payload: &mut [u8; PAYLOAD_LEN],
    words: &mut [u8; FACTOR_LEN],
    device: Option<&[u8; FACTOR_LEN]>,
) -> Result<(), Error> {
    let mut pad = Zeroizing::new([0u8; CHECK_LEN]);
    let mut hash_key = [0u8; HASH_KEY_LEN];
    rng.fill(&mut pad[..])?;
    rng.fill(&mut hash_key)?;
    rng.fill(words)?;

    payload[..4].copy_from_slice(&COMPOSE_MAGIC);
    payload[4] = COMPOSE_VERSION;
    payload[5] = FACTOR_WORDS | if device.is_some() { FACTOR_DEVICE } else { 0 };
    let shares_part = &mut payload[SHARES_PART];
    for (i, byte) in shares_part.iter_mut().enumerate() {
        let c = if i < COMPOSED_KEY_LEN {
            key[i]
        } else {
            pad[i - COMPOSED_KEY_LEN]
        };
        *byte = c ^ words[i] ^ device.map_or(0, |d| d[i]);
    }
    payload[HASH_KEY].copy_from_slice(&hash_key);
    payload[CHECK].copy_from_slice(&check(&hash_key, key, &pad[..]));
    Ok(())
}

/// Forges a composed key that is never computed. The shares' part and the words' factor are drawn
/// independently at random, and the key is whatever their XOR is. The joint check is linear in the
/// key, so each part contributes to it on its own and the key is never assembled, not even for
/// that. The key first exists when [`recover`] rebuilds it.
pub fn forge<E: Entropy + ?Sized>(
    rng: &mut E,
    payload: &mut [u8; PAYLOAD_LEN],
    words: &mut [u8; FACTOR_LEN],
    device: Option<&[u8; FACTOR_LEN]>,
) -> Result<(), Error> {
    rng.fill(words)?;
    payload[..4].copy_from_slice(&COMPOSE_MAGIC);
    payload[4] = COMPOSE_VERSION;
    payload[5] = FACTOR_WORDS | if device.is_some() { FACTOR_DEVICE } else { 0 };
    rng.fill(&mut payload[SHARES_PART])?;
    let mut hash_key = [0u8; 2 * HASH_KEY_LEN];
    rng.fill(&mut hash_key[..HASH_KEY_LEN])?;
    payload[HASH_KEY].copy_from_slice(&hash_key[..HASH_KEY_LEN]);

    // POLYVAL_h(K ‖ len) = POLYVAL_h(shares' part ‖ len) ⊕ POLYVAL_h(words ‖ 0) ⊕ ..., and the pad
    // is the XOR of each part's last 4 bytes, so the check never needs K itself.
    let others = [Some(&*words), device];
    let shares_part = &payload[SHARES_PART];
    let mut hash = Zeroizing::new(mac::tag(&hash_key, &shares_part[..COMPOSED_KEY_LEN]));
    for part in others.iter().flatten() {
        let term = mac::tag_delta(&hash_key[..HASH_KEY_LEN], &part[..COMPOSED_KEY_LEN]);
        mac::xor_into(&mut hash[..], &term);
    }
    let mut check = [hash[0], hash[1], hash[2], hash[3]];
    mac::xor_into(&mut check, &shares_part[COMPOSED_KEY_LEN..]);
    for part in others.iter().flatten() {
        mac::xor_into(&mut check, &part[COMPOSED_KEY_LEN..]);
    }
    payload[CHECK].copy_from_slice(&check);
    Ok(())
}

/// Whether recovered share data holds a composition rather than a plain file.
pub fn is_composed(payload: &[u8]) -> bool {
    payload.len() == PAYLOAD_LEN && payload[..4] == COMPOSE_MAGIC
}

/// Rebuilds the key from the shares' payload, the words' factor and, if the composition has one,
/// the device factor, with one joint check.
pub fn recover(
    payload: &[u8],
    words: &[u8; FACTOR_LEN],
    device: Option<&[u8; FACTOR_LEN]>,
    key: &mut [u8; COMPOSED_KEY_LEN],
) -> Result<(), Error> {
    if !is_composed(payload) {
        return Err(Error::NotComposed);
    }
    let flags = payload[5];
    let known = flags & FACTOR_WORDS != 0 && flags & !(FACTOR_WORDS | FACTOR_DEVICE) == 0;
    if payload[4] != COMPOSE_VERSION || !known {
        return Err(Error::UnsupportedVersion(payload[4]));
    }
    match (flags & FACTOR_DEVICE != 0, device.is_some()) {
        (true, false) => return Err(Error::DeviceRequired),
        (false, true) => return Err(Error::BadParams),
        _ => {}
    }
    let mut c = Zeroizing::new([0u8; FACTOR_LEN]);
    for (i, c) in c.iter_mut().enumerate() {
        *c = payload[SHARES_PART.start + i] ^ words[i] ^ device.map_or(0, |d| d[i]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Spelling, factor_to_words, word, words_to_factor};
    use std::{string::String, vec::Vec};

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
        compose(&key, &mut rng, &mut payload, &mut words, None).unwrap();
        (key, payload, words)
    }

    fn typed(words: &[u8; FACTOR_LEN], spelling: Spelling) -> String {
        let phrase = factor_to_words(words, spelling);
        let list: Vec<&str> = phrase.indices().iter().map(|&i| word(i)).collect();
        list.join(" ")
    }

    #[test]
    fn shares_and_words_together_rebuild_the_key() {
        let (key, payload, words) = composed(1);
        for spelling in [Spelling::English, Spelling::Polyglot] {
            let factor = words_to_factor(&typed(&words, spelling)).unwrap();
            let mut out = [0u8; 32];
            recover(&payload, &factor, None, &mut out).unwrap();
            assert_eq!(out, key);
        }
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
            recover(&payload, &forced, None, &mut out).unwrap();
            assert_eq!(out, other);
        }
    }

    #[test]
    fn wrong_words_and_wrong_shares_fail_the_same_way() {
        let (_, payload, words) = composed(3);
        let (_, other_payload, other_words) = composed(4);
        let mut out = [0u8; 32];
        assert_eq!(
            recover(&payload, &other_words, None, &mut out),
            Err(Error::FactorsDontCombine)
        );
        assert_eq!(
            recover(&other_payload, &words, None, &mut out),
            Err(Error::FactorsDontCombine)
        );
        assert_eq!(out, [0u8; 32], "a failed recovery writes nothing");
    }

    /// Swapping any one word for a different valid word must never open the key: the checksum
    /// usually catches it, and the joint check catches the rest.
    #[test]
    fn a_single_wrong_word_never_opens_the_key() {
        let (_, payload, words) = composed(6);
        for (spelling, modulus) in [(Spelling::English, 2048), (Spelling::Polyglot, 8192)] {
            let indices: Vec<u16> = factor_to_words(&words, spelling).indices().to_vec();
            for position in 0..indices.len() {
                for replacement in [7u16, 500, 1999] {
                    let mut swapped = indices.clone();
                    swapped[position] = (indices[position] + replacement) % modulus;
                    let text: Vec<&str> = swapped.iter().map(|&i| word(i)).collect();
                    match words_to_factor(&text.join(" ")) {
                        Err(Error::BadWords) => {}
                        Ok(factor) => {
                            let mut out = [0u8; 32];
                            let result = recover(&payload, &factor, None, &mut out);
                            assert_eq!(result, Err(Error::FactorsDontCombine));
                        }
                        Err(other) => panic!("unexpected {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn device_factor_is_required_once_composed_with_one() {
        let mut rng = TestRng(8);
        let (mut key, mut device) = ([0u8; 32], [0u8; FACTOR_LEN]);
        rng.fill(&mut key).unwrap();
        rng.fill(&mut device).unwrap();
        let (mut payload, mut words) = ([0u8; PAYLOAD_LEN], [0u8; FACTOR_LEN]);
        compose(&key, &mut rng, &mut payload, &mut words, Some(&device)).unwrap();

        let mut out = [0u8; 32];
        recover(&payload, &words, Some(&device), &mut out).unwrap();
        assert_eq!(out, key);
        assert_eq!(
            recover(&payload, &words, None, &mut out),
            Err(Error::DeviceRequired)
        );
        let mut other_device = device;
        other_device[0] ^= 1;
        assert_eq!(
            recover(&payload, &words, Some(&other_device), &mut out),
            Err(Error::FactorsDontCombine),
            "a wrong device fails exactly like a wrong word"
        );
        let (_, plain, plain_words) = composed(9);
        assert_eq!(
            recover(&plain, &plain_words, Some(&device), &mut out),
            Err(Error::BadParams)
        );
    }

    fn forged(
        seed: u64,
        device: Option<&[u8; FACTOR_LEN]>,
    ) -> ([u8; PAYLOAD_LEN], [u8; FACTOR_LEN]) {
        let (mut payload, mut words) = ([0u8; PAYLOAD_LEN], [0u8; FACTOR_LEN]);
        forge(&mut TestRng(seed), &mut payload, &mut words, device).unwrap();
        (payload, words)
    }

    /// The forged key was never computed, yet it is well defined: the shares' part XOR the words.
    /// Recovery reaching exactly that value also proves the term-by-term check is right.
    #[test]
    fn forged_key_is_the_xor_of_its_parts() {
        for seed in 20..30 {
            let (payload, words) = forged(seed, None);
            let mut out = [0u8; 32];
            recover(&payload, &words, None, &mut out).unwrap();
            let implied: [u8; 32] =
                core::array::from_fn(|i| payload[SHARES_PART.start + i] ^ words[i]);
            assert_eq!(out, implied);
        }
    }

    #[test]
    fn forged_keys_fail_like_composed_ones() {
        let (payload, words) = forged(31, None);
        let (_, other_words) = forged(32, None);
        let mut out = [0u8; 32];
        recover(&payload, &words, None, &mut out).unwrap();
        assert_eq!(
            recover(&payload, &other_words, None, &mut out),
            Err(Error::FactorsDontCombine)
        );

        let mut device = [0u8; FACTOR_LEN];
        TestRng(33).fill(&mut device).unwrap();
        let (payload, words) = forged(34, Some(&device));
        recover(&payload, &words, Some(&device), &mut out).unwrap();
        assert_eq!(
            recover(&payload, &words, None, &mut out),
            Err(Error::DeviceRequired)
        );
        let mut wrong = device;
        wrong[31] ^= 0x40;
        assert_eq!(
            recover(&payload, &words, Some(&wrong), &mut out),
            Err(Error::FactorsDontCombine)
        );
    }

    #[test]
    fn keystrokes_change_the_forged_key() {
        use crate::{Mix, Ripple};
        let mut ripple = Ripple::new();
        ripple.stir(b"keys typed while forging");
        let (mut quiet_payload, mut quiet_words) = ([0u8; PAYLOAD_LEN], [0u8; FACTOR_LEN]);
        let (mut typed_payload, mut typed_words) = ([0u8; PAYLOAD_LEN], [0u8; FACTOR_LEN]);
        forge(
            &mut Mix(TestRng(40), Ripple::new()),
            &mut quiet_payload,
            &mut quiet_words,
            None,
        )
        .unwrap();
        forge(
            &mut Mix(TestRng(40), ripple),
            &mut typed_payload,
            &mut typed_words,
            None,
        )
        .unwrap();
        assert_ne!(quiet_words, typed_words);
        assert_ne!(&quiet_payload[SHARES_PART], &typed_payload[SHARES_PART]);
        let mut out = [0u8; 32];
        recover(&typed_payload, &typed_words, None, &mut out).unwrap();
    }

    #[test]
    fn plain_files_are_not_compositions() {
        let mut out = [0u8; 32];
        assert_eq!(
            recover(b"just a file", &[0; FACTOR_LEN], None, &mut out),
            Err(Error::NotComposed)
        );
    }
}
