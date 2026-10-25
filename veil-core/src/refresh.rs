//! Proactive refresh: re-randomize every share without rebuilding the secret, so shares stolen in
//! different epochs never combine.
//!
//! The dealer works from public parameters and hash keys only. It never reads share data, so the
//! shares can stay apart in separate vaults: each vault sends the dealer a keycard, the dealer
//! sends back one mask per vault, and each vault applies its own mask.

use crate::format::{
    HASH_KEY_LEN, HEADER_LEN, Header, KEY_LEN, KEYCARD_MAGIC, KEYS_OFFSET, KeycardView, MASK_MAGIC,
    PAD_LEN, SetId, ShareView, TAG_LEN, Y_OFFSET, body_len, keycard_len, mask_len, slot,
};
use crate::share::{check_consistent, cross_check, eval};
use crate::{Entropy, Error, MAX_SHARES, SECRET_LEN, mac};
use zeroize::{Zeroize, Zeroizing};

/// The hash half of every pairwise key in a split, plus the parameters a dealer needs. Zeroed when
/// dropped.
pub struct HashKeys {
    /// `keys[i - 1][j - 1]` is the hash key share `i` uses to check share `j`.
    keys: [[[u8; HASH_KEY_LEN]; MAX_SHARES]; MAX_SHARES],
    k: u8,
    n: u8,
    epoch: u32,
    set_id: SetId,
}

impl HashKeys {
    /// Gathers hash keys from a complete set of shares held in one place, after cross-verifying all
    /// of them.
    pub fn collect(shares: &[ShareView<'_>]) -> Result<Self, Error> {
        let mut keys = Self::empty(complete(shares.iter().map(ShareView::header))?);
        cross_check(shares)?;
        for verifier in shares {
            for share in shares.iter().filter(|s| s.index() != verifier.index()) {
                keys.keys[verifier.index() as usize - 1][share.index() as usize - 1]
                    .copy_from_slice(&verifier.key_for(share.index())[..HASH_KEY_LEN]);
            }
        }
        Ok(keys)
    }

    /// Gathers hash keys from one keycard per share, so the shares themselves never meet.
    ///
    /// Keycards cannot be cross-verified. A tampered keycard yields masks that break the affected
    /// tags, which the next `check` or `combine` reports; it cannot make a forged share pass.
    pub fn from_keycards(cards: &[KeycardView<'_>]) -> Result<Self, Error> {
        let mut keys = Self::empty(complete(cards.iter().map(KeycardView::header))?);
        for card in cards {
            for other in (1..=keys.n).filter(|&j| j != card.index()) {
                keys.keys[card.index() as usize - 1][other as usize - 1]
                    .copy_from_slice(card.hash_key_for(other));
            }
        }
        Ok(keys)
    }

    fn empty(header: Header) -> Self {
        Self {
            keys: [[[0; HASH_KEY_LEN]; MAX_SHARES]; MAX_SHARES],
            k: header.k,
            n: header.n,
            epoch: header.epoch,
            set_id: header.set_id,
        }
    }
}

impl Drop for HashKeys {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

/// The header of a complete set: one split and epoch, every index from 1 to n present once.
fn complete(headers: impl ExactSizeIterator<Item = Header> + Clone) -> Result<Header, Error> {
    check_consistent(headers.clone())?;
    let count = headers.len();
    let mut headers = headers;
    let Some(first) = headers.next() else {
        return Err(Error::NotEnoughShares { have: 0, need: 2 });
    };
    if count != first.n as usize {
        return Err(Error::NotEnoughShares {
            have: count as u8,
            need: first.n,
        });
    }
    Ok(first)
}

/// Writes `share`'s keycard into `out`, which must be [`keycard_len`]`(n)` bytes: the share's
/// header and the hash half of each of its keys. No share data and no pads.
///
/// A keycard reveals nothing about the secret, but whoever holds it and another share could forge
/// that share's tag towards this one. It should reach only the dealer and be destroyed after use.
pub fn keycard(share: &ShareView<'_>, out: &mut [u8]) -> Result<(), Error> {
    let header = share.header();
    if out.len() != keycard_len(header.n) {
        return Err(Error::BadLength);
    }
    header.write(out, KEYCARD_MAGIC);
    for other in (1..=header.n).filter(|&j| j != header.x) {
        let at = HEADER_LEN + slot(header.x, other) * HASH_KEY_LEN;
        out[at..at + HASH_KEY_LEN].copy_from_slice(&share.key_for(other)[..HASH_KEY_LEN]);
    }
    Ok(())
}

/// Writes one mask file per share into `masks`, each [`mask_len`]`(n)` bytes and ordered by share
/// index. Applying mask `x` to share `x` (see [`apply`]) moves it to the next epoch: its data gains a
/// fresh random sharing of zero, every pad is replaced, and every tag is corrected to match.
///
/// Each mask must reach only its own share and be destroyed after use: anyone holding a mask can
/// convert that share between the two epochs.
pub fn deal<E: Entropy + ?Sized>(
    keys: &HashKeys,
    rng: &mut E,
    masks: &mut [&mut [u8]],
) -> Result<(), Error> {
    let (k, n) = (keys.k, keys.n);
    let next = keys.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
    if masks.len() != n as usize || masks.iter().any(|m| m.len() != mask_len(n)) {
        return Err(Error::BadLength);
    }
    for (i, mask) in masks.iter_mut().enumerate() {
        mask.zeroize();
        let target = Header {
            k,
            n,
            x: i as u8 + 1,
            epoch: keys.epoch,
            set_id: keys.set_id,
        };
        target.write(mask, MASK_MAGIC);
        raw_mut(mask)[8..12].copy_from_slice(&(keys.epoch ^ next).to_be_bytes());
    }

    // One fresh random polynomial per byte with a zero constant term, so the secret stays put.
    let mut coeffs = Zeroizing::new([0u8; MAX_SHARES - 1]);
    let coeffs = &mut coeffs[..k as usize - 1];
    for b in 0..SECRET_LEN {
        rng.fill(coeffs)?;
        for (j, mask) in masks.iter_mut().enumerate() {
            raw_mut(mask)[Y_OFFSET + b] = eval(0, coeffs, j as u8 + 1);
        }
    }

    // Hash keys stay; every pad is replaced.
    for (i, mask) in masks.iter_mut().enumerate() {
        for j in (0..n as usize).filter(|&j| j != i) {
            let at = KEYS_OFFSET + slot(i as u8 + 1, j as u8 + 1) * KEY_LEN + HASH_KEY_LEN;
            rng.fill(&mut raw_mut(mask)[at..at + PAD_LEN])?;
        }
    }

    // Every pad and body change is in place, so each tag correction is the hash of its share's
    // body change plus its pad change.
    let body = body_len(n);
    for j in 0..n as usize {
        for i in (0..n as usize).filter(|&i| i != j) {
            let (xi, xj) = (i as u8 + 1, j as u8 + 1);
            let mut correction = mac::tag_delta(&keys.keys[i][j], &raw(masks[j])[..body]);
            let at = KEYS_OFFSET + slot(xi, xj) * KEY_LEN + HASH_KEY_LEN;
            mac::xor_into(&mut correction, &raw(masks[i])[at..at + PAD_LEN]);
            let at = body + slot(xj, xi) * TAG_LEN;
            raw_mut(masks[j])[at..at + TAG_LEN].copy_from_slice(&correction);
        }
    }
    Ok(())
}

/// Moves one share to the next epoch by XORing in its mask file from [`deal`]. Refuses a mask made
/// for any other share, set or epoch.
pub fn apply(share: &mut [u8], mask: &[u8]) -> Result<(), Error> {
    let header = ShareView::parse(share)?.header();
    let target = Header::parse(mask, MASK_MAGIC, mask_len).map_err(|_| Error::WrongMask)?;
    if target != header {
        return Err(Error::WrongMask);
    }
    let next = header.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
    let delta = raw(mask);
    let fixed_fields_untouched = delta[..8]
        .iter()
        .chain(&delta[12..HEADER_LEN])
        .all(|&b| b == 0);
    if !fixed_fields_untouched || delta[8..12] != (header.epoch ^ next).to_be_bytes() {
        return Err(Error::WrongMask);
    }
    mac::xor_into(share, delta);
    Ok(())
}

/// The share-sized XOR mask inside a mask file.
fn raw(mask: &[u8]) -> &[u8] {
    &mask[HEADER_LEN..]
}

fn raw_mut(mask: &mut [u8]) -> &mut [u8] {
    &mut mask[HEADER_LEN..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::share_len;
    use crate::share::reconstruct;
    use crate::{MAX_FILE, Secret, combine, split, verify};
    use std::{vec, vec::Vec};

    /// Deterministic SplitMix64 stream. For tests only.
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

    fn make(k: u8, n: u8, file: &[u8], seed: u64) -> Vec<Vec<u8>> {
        let mut secret = Secret::new();
        secret.load(file).unwrap();
        let mut shares = vec![vec![0; share_len(n)]; n as usize];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        split(&secret, k, n, &mut TestRng(seed), &mut refs).unwrap();
        shares
    }

    fn views(shares: &[Vec<u8>]) -> Vec<ShareView<'_>> {
        shares
            .iter()
            .map(|s| ShareView::parse(s).unwrap())
            .collect()
    }

    fn keycards(shares: &[Vec<u8>]) -> Vec<Vec<u8>> {
        views(shares)
            .iter()
            .map(|v| {
                let mut card = vec![0; keycard_len(v.total())];
                keycard(v, &mut card).unwrap();
                card
            })
            .collect()
    }

    fn card_views(cards: &[Vec<u8>]) -> Vec<KeycardView<'_>> {
        cards
            .iter()
            .map(|c| KeycardView::parse(c).unwrap())
            .collect()
    }

    fn masks_for(keys: &HashKeys, n: u8, seed: u64) -> Vec<Vec<u8>> {
        let mut masks = vec![vec![0; mask_len(n)]; n as usize];
        let mut refs: Vec<&mut [u8]> = masks.iter_mut().map(Vec::as_mut_slice).collect();
        deal(keys, &mut TestRng(seed), &mut refs).unwrap();
        masks
    }

    /// Refreshes a complete set held in one place, returning the next epoch's shares.
    fn refresh(shares: &[Vec<u8>], seed: u64) -> Vec<Vec<u8>> {
        let keys = HashKeys::collect(&views(shares)).unwrap();
        let masks = masks_for(&keys, shares.len() as u8, seed);
        let mut next = shares.to_vec();
        for (share, mask) in next.iter_mut().zip(&masks) {
            apply(share, mask).unwrap();
        }
        next
    }

    fn recover(shares: &[&Vec<u8>]) -> Result<Vec<u8>, Error> {
        let views: Vec<ShareView<'_>> = shares
            .iter()
            .map(|s| ShareView::parse(s).unwrap())
            .collect();
        let mut out = Secret::new();
        combine(&views, &mut out)?;
        Ok(out.file()?.to_vec())
    }

    #[test]
    fn refresh_keeps_the_file_and_advances_the_epoch() {
        for (k, n) in [(2, 2), (3, 5), (4, 7)] {
            let file = vec![0x42; MAX_FILE];
            let epoch0 = make(k, n, &file, 1);
            let epoch1 = refresh(&epoch0, 2);
            let epoch2 = refresh(&epoch1, 3);
            assert!(views(&epoch2).iter().all(|v| v.epoch() == 2));
            assert_eq!(verify(&views(&epoch2)), Ok(()), "k={k} n={n}");
            let picked: Vec<&Vec<u8>> = epoch2.iter().rev().take(k as usize).collect();
            assert_eq!(recover(&picked).unwrap(), file, "k={k} n={n}");
        }
    }

    /// The vault-by-vault ceremony gives exactly the masks the all-in-one-place refresh gives.
    #[test]
    fn keycards_deal_the_same_masks_as_the_shares() {
        let shares = make(3, 5, b"apart or together", 16);
        let cards = keycards(&shares);
        assert!(cards.iter().all(|c| c.len() == keycard_len(5)));
        let from_cards = HashKeys::from_keycards(&card_views(&cards)).unwrap();
        let from_shares = HashKeys::collect(&views(&shares)).unwrap();
        assert_eq!(
            masks_for(&from_cards, 5, 17),
            masks_for(&from_shares, 5, 17)
        );
    }

    #[test]
    fn ceremony_with_shares_apart_keeps_the_file() {
        let file = b"no two shares ever met".to_vec();
        let shares = make(3, 5, &file, 18);
        let keys = HashKeys::from_keycards(&card_views(&keycards(&shares))).unwrap();
        let masks = masks_for(&keys, 5, 19);
        let mut next = shares.clone();
        for (share, mask) in next.iter_mut().zip(&masks) {
            apply(share, mask).unwrap();
        }
        assert_eq!(verify(&views(&next)), Ok(()));
        assert_eq!(recover(&[&next[4], &next[0], &next[2]]).unwrap(), file);
    }

    #[test]
    fn refresh_changes_every_share() {
        let epoch0 = make(3, 5, b"same secret, new shares", 4);
        let epoch1 = refresh(&epoch0, 5);
        for (old, new) in epoch0.iter().zip(&epoch1) {
            let differing = old[Y_OFFSET..KEYS_OFFSET]
                .iter()
                .zip(&new[Y_OFFSET..KEYS_OFFSET]);
            assert!(differing.filter(|(a, b)| a != b).count() > SECRET_LEN * 9 / 10);
        }
    }

    #[test]
    fn epochs_do_not_mix() {
        let epoch0 = make(3, 5, b"stolen slowly", 6);
        let epoch1 = refresh(&epoch0, 7);
        assert_eq!(
            recover(&[&epoch0[0], &epoch1[1], &epoch1[2]]),
            Err(Error::MixedSets)
        );
    }

    /// Even with the epoch field forged and the tags ignored, an old share does not fit the new
    /// curve: the rebuilt block is garbage.
    #[test]
    fn old_share_with_forged_epoch_rebuilds_garbage() {
        let file = b"stolen slowly".to_vec();
        let epoch0 = make(3, 5, &file, 8);
        let epoch1 = refresh(&epoch0, 9);
        let mut old = epoch0[0].clone();
        old[8..12].copy_from_slice(&1u32.to_be_bytes());
        let set = [old, epoch1[1].clone(), epoch1[2].clone()];
        let mut out = Secret::new();
        reconstruct(&views(&set), &mut out);
        assert_ne!(out.file().ok(), Some(&file[..]));
    }

    /// With k = 2, an old share s + a·1 and a new share s + (a + c)·2, with c from the refresh,
    /// are a one-to-one image of (a, c): uniform over all 65,536 pairs whatever s is.
    #[test]
    fn one_old_and_one_new_share_reveal_nothing() {
        let mut seen = vec![false; 1 << 16];
        for s in [0x00, 0x3c, 0xff] {
            seen.fill(false);
            for a in 0..=255u8 {
                for c in 0..=255u8 {
                    let old = eval(s, &[a], 1);
                    let new = eval(s, &[a], 2) ^ eval(0, &[c], 2);
                    let pair = (old as usize) << 8 | new as usize;
                    assert!(!seen[pair], "s={s:#04x}");
                    seen[pair] = true;
                }
            }
        }
    }

    #[test]
    fn refresh_needs_every_share_or_keycard() {
        let shares = make(3, 5, b"all hands", 10);
        assert!(matches!(
            HashKeys::collect(&views(&shares[..4])),
            Err(Error::NotEnoughShares { have: 4, need: 5 })
        ));
        let cards = keycards(&shares);
        assert!(matches!(
            HashKeys::from_keycards(&card_views(&cards[..4])),
            Err(Error::NotEnoughShares { have: 4, need: 5 })
        ));
    }

    #[test]
    fn keycards_from_different_sets_do_not_mix() {
        let mut cards = keycards(&make(3, 5, b"set a", 20));
        cards[3] = keycards(&make(3, 5, b"set b", 21)).swap_remove(3);
        assert!(matches!(
            HashKeys::from_keycards(&card_views(&cards)),
            Err(Error::MixedSets)
        ));
    }

    #[test]
    fn refresh_refuses_a_tampered_set() {
        let mut shares = make(3, 5, b"all hands", 11);
        shares[2][Y_OFFSET + 9] ^= 0x10;
        assert!(matches!(
            HashKeys::collect(&views(&shares)),
            Err(Error::TamperDetected(_))
        ));
    }

    /// A doctored keycard cannot be caught at dealing time, but the tags it corrects come out wrong,
    /// so the refreshed set fails cross-verification rather than passing silently.
    #[test]
    fn tampered_keycard_is_caught_afterwards() {
        let shares = make(3, 5, b"doctored card", 22);
        let mut cards = keycards(&shares);
        cards[1][HEADER_LEN + 3] ^= 0x01;
        let keys = HashKeys::from_keycards(&card_views(&cards)).unwrap();
        let masks = masks_for(&keys, 5, 23);
        let mut next = shares.clone();
        for (share, mask) in next.iter_mut().zip(&masks) {
            apply(share, mask).unwrap();
        }
        assert!(matches!(
            verify(&views(&next)),
            Err(Error::TamperDetected(_))
        ));
    }

    #[test]
    fn mask_cannot_be_applied_twice() {
        let shares = make(3, 5, b"once only", 12);
        let masks = masks_for(&HashKeys::collect(&views(&shares)).unwrap(), 5, 13);
        let mut share = shares[0].clone();
        apply(&mut share, &masks[0]).unwrap();
        assert_eq!(apply(&mut share, &masks[0]), Err(Error::WrongMask));
    }

    #[test]
    fn mask_for_another_share_or_set_is_refused() {
        let shares = make(3, 5, b"wrong vault", 14);
        let masks = masks_for(&HashKeys::collect(&views(&shares)).unwrap(), 5, 15);
        let mut share = shares[1].clone();
        assert_eq!(apply(&mut share, &masks[2]), Err(Error::WrongMask));

        let other = make(3, 5, b"other set", 24);
        let other_masks = masks_for(&HashKeys::collect(&views(&other)).unwrap(), 5, 25);
        assert_eq!(apply(&mut share, &other_masks[1]), Err(Error::WrongMask));
        assert_eq!(
            share, shares[1],
            "a refused mask must leave the share untouched"
        );
    }
}
