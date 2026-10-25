//! Randomness extraction: turns raw, imperfect hardware noise into bytes statistically close to
//! uniform, with no computational assumption.
//!
//! Each 64-byte raw block is multiplied by a Toeplitz matrix over GF(2) fixed by a public seed.
//! Toeplitz matrices form a universal hash family, so by the Leftover Hash Lemma, if a block carries
//! at least k bits of min-entropy, its m output bits are within 2^-((k - m) / 2) of uniform, even to
//! someone who knows the seed. The seed only has to be uniform and chosen independently of the
//! noise, which is why it can be made once from dice and then reused.
//!
//! Bit `b` of a byte string is bit `b % 8` of byte `b / 8`, least significant first.

use crate::Error;
use zeroize::Zeroize;

/// Raw bytes per block: n = 512 input bits.
pub const RAW_BLOCK: usize = 64;

/// Most output bytes per block: m ≤ 128 bits.
pub const MAX_OUTPUT: usize = 16;

/// Seed bytes: n + m − 1 = 639 bits are used; the top bit of the last byte is ignored.
pub const SEED_LEN: usize = 80;

/// Die rolls for a seed: 6^272 > 2^703, so the seed is within 2^-64 of uniform.
pub const DICE_ROLLS: usize = 272;

/// Output is capped at k − 128 bits, so each block is within 2^-64 of uniform at worst.
const MARGIN_BITS: u32 = 128;

/// A Toeplitz extractor for one source, sized by that source's min-entropy.
pub struct Toeplitz {
    seed: [u64; SEED_LEN / 8],
    out_bits: usize,
    security_bits: u32,
}

impl Toeplitz {
    /// `block_min_entropy` is k: the min-entropy, in bits, that each 64-byte raw block carries.
    pub fn new(seed: &[u8; SEED_LEN], block_min_entropy: u32) -> Result<Self, Error> {
        let k = block_min_entropy.min(8 * RAW_BLOCK as u32);
        let out_bits = k.saturating_sub(MARGIN_BITS).min(8 * MAX_OUTPUT as u32) / 8 * 8;
        if out_bits == 0 {
            return Err(Error::SourceTooWeak);
        }
        let mut words = [0u64; SEED_LEN / 8];
        for (word, chunk) in words.iter_mut().zip(seed.chunks_exact(8)) {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        Ok(Self {
            seed: words,
            out_bits: out_bits as usize,
            security_bits: (k - out_bits) / 2,
        })
    }

    /// Output bytes per raw block.
    pub fn output_len(&self) -> usize {
        self.out_bits / 8
    }

    /// Each block's output is within 2^-security_bits of uniform.
    pub fn security_bits(&self) -> u32 {
        self.security_bits
    }

    /// Output bit i is the XOR over j of seed bit (i − j + 511) AND raw bit j. With the raw block
    /// reversed, that is the parity of seed bits i..i+512 AND the reversed block.
    pub fn extract(&self, raw: &[u8; RAW_BLOCK], out: &mut [u8]) {
        let mut reversed = [0u64; RAW_BLOCK / 8];
        for (q, word) in reversed.iter_mut().enumerate() {
            let mut bytes = [0; 8];
            for (t, byte) in bytes.iter_mut().enumerate() {
                *byte = raw[RAW_BLOCK - 1 - (8 * q + t)].reverse_bits();
            }
            *word = u64::from_le_bytes(bytes);
        }
        out[..self.output_len()].fill(0);
        for i in 0..self.out_bits {
            let (first, shift) = (i / 64, i % 64);
            let mut acc = 0u64;
            for (w, &r) in reversed.iter().enumerate() {
                let low = self.seed[first + w] >> shift;
                let high = if shift == 0 {
                    0
                } else {
                    self.seed[first + w + 1] << (64 - shift)
                };
                acc ^= (low | high) & r;
            }
            out[i / 8] |= ((acc.count_ones() & 1) as u8) << (i % 8);
        }
        reversed.zeroize();
    }
}

/// Turns [`DICE_ROLLS`] rolls of a fair six-sided die (values 1 to 6, first roll most significant)
/// into a seed: the rolls read as one base-6 number, reduced modulo 2^639.
pub fn seed_from_dice(rolls: &[u8; DICE_ROLLS]) -> Result<[u8; SEED_LEN], Error> {
    let mut seed = [0; SEED_LEN];
    base6_to_bits(rolls, &mut seed)?;
    seed[SEED_LEN - 1] &= 0x7f;
    Ok(seed)
}

/// Writes the low bits of the base-6 number `rolls` (each 1 to 6) into `out`, little-endian.
fn base6_to_bits(rolls: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let mut limbs = [0u32; 23];
    for &roll in rolls {
        if !(1..=6).contains(&roll) {
            return Err(Error::BadParams);
        }
        let mut carry = (roll - 1) as u64;
        for limb in limbs.iter_mut() {
            let value = *limb as u64 * 6 + carry;
            *limb = value as u32;
            carry = value >> 32;
        }
    }
    for (chunk, limb) in out.chunks_mut(4).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes()[..chunk.len()]);
    }
    limbs.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bit(bytes: &[u8], b: usize) -> u8 {
        bytes[b / 8] >> (b % 8) & 1
    }

    /// The matrix definition, written out directly: out_i = XOR over j of s[i − j + n − 1] · x[j].
    fn toeplitz_reference(seed: &[u8], input: &[u8], n: usize, m: usize, out: &mut [u8]) {
        out.fill(0);
        for i in 0..m {
            let mut acc = 0;
            for j in 0..n {
                acc ^= bit(seed, i + n - 1 - j) & bit(input, j);
            }
            out[i / 8] |= acc << (i % 8);
        }
    }

    /// Toeplitz hashing is universal: for any non-zero difference d between two inputs, exactly a
    /// 2^-m fraction of seeds sends d to zero, so the two inputs collide. Exhaustive over every
    /// seed and every d, for two small sizes. The Leftover Hash Lemma needs exactly this.
    #[test]
    fn construction_is_universal() {
        for (n, m) in [(6, 3), (8, 4)] {
            let seeds = 1u32 << (n + m - 1);
            for d in 1u32..1 << n {
                let collisions = (0..seeds)
                    .filter(|s| {
                        let mut out = [0u8];
                        toeplitz_reference(&s.to_le_bytes(), &d.to_le_bytes(), n, m, &mut out);
                        out[0] == 0
                    })
                    .count();
                assert_eq!(collisions as u32, seeds >> m, "n={n} m={m} d={d:#b}");
            }
        }
    }

    #[test]
    fn fast_extractor_matches_the_matrix_definition() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for k in [512, 384, 256, 200] {
            for _ in 0..50 {
                let seed: [u8; SEED_LEN] = core::array::from_fn(|_| next());
                let raw: [u8; RAW_BLOCK] = core::array::from_fn(|_| next());
                let extractor = Toeplitz::new(&seed, k).unwrap();
                let m = extractor.output_len();
                let (mut fast, mut slow) = ([0u8; MAX_OUTPUT], [0u8; MAX_OUTPUT]);
                extractor.extract(&raw, &mut fast);
                toeplitz_reference(&seed, &raw, 8 * RAW_BLOCK, 8 * m, &mut slow);
                assert_eq!(fast[..m], slow[..m], "k={k}");
            }
        }
    }

    #[test]
    fn output_is_sized_by_min_entropy() {
        let seed = [0x5a; SEED_LEN];
        let sizes = [
            (512, 16, 192),
            (448, 16, 160),
            (256, 16, 64),
            (192, 8, 64),
            (140, 1, 66),
        ];
        for (k, bytes, security) in sizes {
            let extractor = Toeplitz::new(&seed, k).unwrap();
            assert_eq!(extractor.output_len(), bytes, "k={k}");
            assert_eq!(extractor.security_bits(), security, "k={k}");
        }
        assert!(matches!(
            Toeplitz::new(&seed, 135),
            Err(Error::SourceTooWeak)
        ));
    }

    /// 40 rolls fit in a u128, so the bignum conversion can be checked against plain arithmetic.
    #[test]
    fn dice_conversion_matches_plain_arithmetic() {
        let rolls: [u8; 40] = core::array::from_fn(|i| (i * 7 % 6) as u8 + 1);
        let expected = rolls
            .iter()
            .fold(0u128, |acc, &r| acc * 6 + (r - 1) as u128);
        let mut out = [0u8; 16];
        base6_to_bits(&rolls, &mut out).unwrap();
        assert_eq!(u128::from_le_bytes(out), expected);
    }

    #[test]
    fn dice_seed_edges() {
        assert_eq!(seed_from_dice(&[1; DICE_ROLLS]).unwrap(), [0; SEED_LEN]);
        let top = seed_from_dice(&[6; DICE_ROLLS]).unwrap();
        assert_eq!(top[SEED_LEN - 1] & 0x80, 0, "bit 639 is always cleared");
        let mut bad = [3; DICE_ROLLS];
        bad[100] = 7;
        assert!(matches!(seed_from_dice(&bad), Err(Error::BadParams)));
    }
}
