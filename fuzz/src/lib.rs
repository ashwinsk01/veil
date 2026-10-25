//! What the fuzz targets share: a genuine set of shares, keycards and masks to tamper with, and
//! deterministic randomness to make them.

use std::sync::OnceLock;
use veil_core::{
    Entropy, Error, HashKeys, KeycardView, Secret, ShareView, keycard_len, mask_len, share_len,
};

pub const K: u8 = 3;
pub const N: u8 = 5;

/// SplitMix64. Fuzzing needs runs that repeat exactly; nothing here protects a real secret.
pub struct Counter(pub u64);

impl Entropy for Counter {
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

pub struct Fixture {
    pub file: Vec<u8>,
    pub shares: Vec<Vec<u8>>,
    pub keycards: Vec<Vec<u8>>,
    pub masks: Vec<Vec<u8>>,
}

/// A 3-of-5 split of a fixed file, each share's keycard, and the masks dealt from those keycards.
pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let file: Vec<u8> = (0..200u16).map(|i| (i * 7 + 3) as u8).collect();
        let mut secret = Secret::new();
        secret.load(&file).unwrap();
        let mut rng = Counter(1);
        let mut shares = vec![vec![0u8; share_len(N)]; N as usize];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(|s| &mut s[..]).collect();
        veil_core::split(&secret, K, N, &mut rng, &mut refs).unwrap();

        let mut keycards = vec![vec![0u8; keycard_len(N)]; N as usize];
        for (share, card) in shares.iter().zip(&mut keycards) {
            veil_core::keycard(&ShareView::parse(share).unwrap(), card).unwrap();
        }
        let cards: Vec<KeycardView<'_>> =
            keycards.iter().map(|c| KeycardView::parse(c).unwrap()).collect();
        let keys = HashKeys::from_keycards(&cards).unwrap();
        let mut masks = vec![vec![0u8; mask_len(N)]; N as usize];
        let mut refs: Vec<&mut [u8]> = masks.iter_mut().map(|m| &mut m[..]).collect();
        veil_core::deal(&keys, &mut rng, &mut refs).unwrap();
        Fixture {
            file,
            shares,
            keycards,
            masks,
        }
    })
}

/// Edits `bytes` as `ops` says, three bytes per edit: a big-endian offset, then a byte to XOR in
/// there. XORing in zero would change nothing, so it truncates at that offset instead, which tests
/// lengths too.
pub fn edit(bytes: &mut Vec<u8>, ops: &[u8]) {
    for op in ops.chunks_exact(3) {
        if bytes.is_empty() {
            return;
        }
        let at = u16::from_be_bytes([op[0], op[1]]) as usize % bytes.len();
        match op[2] {
            0 => bytes.truncate(at),
            flip => bytes[at] ^= flip,
        }
    }
}

/// Combines whichever shares `pick` selects. Whenever that succeeds, the file must be the original:
/// no edit may ever change what comes out, only stop it.
pub fn combine_or_refuse(shares: &[Vec<u8>], pick: u8) {
    let views: Vec<ShareView<'_>> = shares
        .iter()
        .enumerate()
        .filter(|(i, _)| pick >> i & 1 == 1)
        .filter_map(|(_, s)| ShareView::parse(s).ok())
        .collect();
    let mut out = Secret::new();
    if veil_core::combine(&views, &mut out).is_ok() {
        assert_eq!(out.file().unwrap(), fixture().file, "tampered shares rebuilt another file");
    }
    let _ = veil_core::verify(&views);
}
