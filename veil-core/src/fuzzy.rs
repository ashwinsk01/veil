//! Fuzzy extractor: turns a noisy physical response, such as a PUF reading, into the same uniform
//! factor every time, with no computational assumption.
//!
//! Code-offset construction (Dodis, Reyzin and Smith, 2004). At enrollment, each 24-bit block of
//! the response w is XORed with a random codeword of the extended binary Golay code [24, 12, 8],
//! and the result is stored as public helper data. A later reading that differs from w in at most
//! 3 bits per block decodes back to exactly w. Each block's helper data leaks at most 12 bits of
//! w, and the Toeplitz extractor (see `extract`) is sized for what remains.
//!
//! Physical errors come in bursts: one bad read flips neighbouring bits together. So block j of
//! each 504-bit chunk takes every 21st bit starting at bit j, and a burst of up to 21 neighbouring
//! errors costs each block at most one.
//!
//! A reading that is too noisy is not reported as such: it yields a wrong factor, which the
//! composition's single joint check rejects like any other wrong factor. That keeps decoding
//! failures from becoming an oracle about the response.

use crate::compose::FACTOR_LEN;
use crate::extract::{MAX_OUTPUT, RAW_BLOCK, SEED_LEN, Toeplitz};
use crate::{Entropy, Error};
use zeroize::Zeroizing;

/// Golay blocks per extractor input: 21 × 24 = 504 response bits.
const BLOCKS_PER_CHUNK: usize = 21;

/// Response bytes per chunk.
pub const CHUNK_BYTES: usize = BLOCKS_PER_CHUNK * 3;

/// Helper data leaks at most 12 bits per Golay block.
const LEAK_PER_CHUNK: u32 = 12 * BLOCKS_PER_CHUNK as u32;

/// Most chunks one enrollment may use.
pub const MAX_CHUNKS: u8 = 64;

pub const FUZZY_MAGIC: [u8; 4] = *b"VFZX";
const FUZZY_VERSION: u8 = 1;
const HELPER_HEADER: usize = 8 + SEED_LEN;

/// Rows of B in the generator matrix G = [I | B]. The first 11 are left rotations of 11011100010
/// with a 1 appended; the last is eleven 1s and a 0. Bit 11 of each row is its first entry.
const B: [u16; 12] = golay_b();

const fn golay_b() -> [u16; 12] {
    let base: u16 = 0b110_1110_0010;
    let mut rows = [0u16; 12];
    let mut i = 0;
    while i < 11 {
        let rotated = ((base << i) | (base >> (11 - i))) & 0x7ff;
        rows[i] = (rotated << 1) | 1;
        i += 1;
    }
    rows[11] = 0x7ff << 1;
    rows
}

/// The row vector `v` times B.
fn times_b(v: u16) -> u16 {
    let mut out = 0;
    for (j, &row) in B.iter().enumerate() {
        out ^= row & 0u16.wrapping_sub(v >> (11 - j) & 1);
    }
    out
}

/// The codeword for a 12-bit message: the message, then the message times B.
fn codeword(message: u16) -> u32 {
    (message as u32) << 12 | times_b(message) as u32
}

fn all_ones_if(condition: bool) -> u16 {
    0u16.wrapping_sub(condition as u16)
}

/// Decodes a 24-bit word with at most 3 errors back to its 12-bit message (MacWilliams and Sloane's
/// algorithm for G = [I | B], which works because B is symmetric and B² = I). Every case is
/// evaluated, so the running time does not depend on where the errors are. An uncorrectable word
/// returns its first half unchanged.
fn decode(word: u32) -> u16 {
    let (first, second) = ((word >> 12) as u16, (word & 0xfff) as u16);
    let syndrome = times_b(first) ^ second;
    let back = times_b(syndrome);
    let (mut error, mut found) = (0u16, 0u16);

    // Errors only in the second half.
    let take = all_ones_if(syndrome.count_ones() <= 3) & !found;
    found |= take;
    // One error in the first half at i, at most two in the second.
    for (i, &row) in B.iter().enumerate() {
        let take = all_ones_if((syndrome ^ row).count_ones() <= 2) & !found;
        error |= (1 << (11 - i)) & take;
        found |= take;
    }
    // Errors only in the first half.
    let take = all_ones_if(back.count_ones() <= 3) & !found;
    error |= back & take;
    found |= take;
    // At most two errors in the first half, one in the second at i.
    for &row in &B {
        let take = all_ones_if((back ^ row).count_ones() <= 2) & !found;
        error |= (back ^ row) & take;
        found |= take;
    }
    first ^ (error & found)
}

/// Min-entropy left in one chunk after its helper data, for a response with `min_entropy_256` / 256
/// bits of min-entropy per bit.
fn chunk_min_entropy(min_entropy_256: u8) -> u32 {
    (8 * CHUNK_BYTES as u32 * min_entropy_256 as u32 / 256).saturating_sub(LEAK_PER_CHUNK)
}

/// Response chunks needed to extract a full factor from a source with `min_entropy_256` / 256 bits
/// of min-entropy per response bit.
pub fn chunks_needed(min_entropy_256: u8) -> Result<u8, Error> {
    let extractor = Toeplitz::new(&[0; SEED_LEN], chunk_min_entropy(min_entropy_256))?;
    let chunks = FACTOR_LEN.div_ceil(extractor.output_len());
    if chunks > MAX_CHUNKS as usize {
        return Err(Error::SourceTooWeak);
    }
    Ok(chunks as u8)
}

/// Each chunk's share of the factor is within 2^-bits of uniform.
pub fn chunk_security_bits(min_entropy_256: u8) -> Result<u32, Error> {
    Ok(Toeplitz::new(&[0; SEED_LEN], chunk_min_entropy(min_entropy_256))?.security_bits())
}

/// Response bytes for an enrollment of `chunks` chunks.
pub const fn response_len(chunks: u8) -> usize {
    chunks as usize * CHUNK_BYTES
}

/// Helper data bytes for an enrollment of `chunks` chunks.
pub const fn helper_len(chunks: u8) -> usize {
    HELPER_HEADER + response_len(chunks)
}

/// Enrolls a response: writes public helper data and the factor the response stands for.
///
/// `min_entropy_256` is a claim about the source, in 1/256ths of a bit per response bit, and fixes
/// how many chunks the response must have (see [`chunks_needed`]). The seed fixes the extractor;
/// it can be public but must be uniform and independent of the source, like the one from dice.
pub fn enroll<E: Entropy + ?Sized>(
    response: &[u8],
    min_entropy_256: u8,
    seed: &[u8; SEED_LEN],
    rng: &mut E,
    helper: &mut [u8],
    factor: &mut [u8; FACTOR_LEN],
) -> Result<(), Error> {
    let chunks = chunks_needed(min_entropy_256)?;
    if response.len() != response_len(chunks) || helper.len() != helper_len(chunks) {
        return Err(Error::BadLength);
    }
    helper[..4].copy_from_slice(&FUZZY_MAGIC);
    helper[4] = FUZZY_VERSION;
    helper[5] = min_entropy_256;
    helper[6] = chunks;
    helper[7] = 0;
    helper[8..HELPER_HEADER].copy_from_slice(seed);
    let mut message = Zeroizing::new([0u8; 2]);
    let chunks = response
        .chunks_exact(CHUNK_BYTES)
        .zip(helper[HELPER_HEADER..].chunks_exact_mut(CHUNK_BYTES));
    for (chunk, offsets) in chunks {
        for (j, out) in offsets.chunks_exact_mut(3).enumerate() {
            rng.fill(&mut message[..])?;
            let offset = codeword(u16::from_be_bytes(*message) & 0xfff) ^ gather(chunk, j);
            out.copy_from_slice(&offset.to_be_bytes()[1..]);
        }
    }
    extract_factor(response, min_entropy_256, seed, factor)
}

/// Rebuilds the factor from a fresh reading and the helper data from [`enroll`]. A reading too far
/// from the enrolled one gives a wrong factor, not an error.
pub fn reproduce(
    response: &[u8],
    helper: &[u8],
    factor: &mut [u8; FACTOR_LEN],
) -> Result<(), Error> {
    if helper.len() < HELPER_HEADER || helper[..4] != FUZZY_MAGIC {
        return Err(Error::BadMagic);
    }
    if helper[4] != FUZZY_VERSION {
        return Err(Error::UnsupportedVersion(helper[4]));
    }
    let (min_entropy_256, chunks) = (helper[5], helper[6]);
    if chunks_needed(min_entropy_256)? != chunks
        || helper.len() != helper_len(chunks)
        || response.len() != response_len(chunks)
    {
        return Err(Error::BadLength);
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&helper[8..HELPER_HEADER]);

    let mut enrolled = Zeroizing::new([0u8; response_len(MAX_CHUNKS)]);
    let chunks = response
        .chunks_exact(CHUNK_BYTES)
        .zip(helper[HELPER_HEADER..].chunks_exact(CHUNK_BYTES))
        .zip(enrolled.chunks_exact_mut(CHUNK_BYTES));
    for ((chunk, offsets), out) in chunks {
        for (j, offset) in offsets.chunks_exact(3).enumerate() {
            let offset = block_bits(offset);
            let corrected = codeword(decode(gather(chunk, j) ^ offset)) ^ offset;
            scatter(out, j, corrected);
        }
    }
    extract_factor(&enrolled[..response.len()], min_entropy_256, &seed, factor)
}

fn block_bits(block: &[u8]) -> u32 {
    u32::from_be_bytes([0, block[0], block[1], block[2]])
}

/// Bit `at` of a byte string, most significant bit of each byte first.
fn bit_of(bytes: &[u8], at: usize) -> u32 {
    (bytes[at / 8] >> (7 - at % 8) & 1) as u32
}

/// Block `j` of a chunk: every 21st bit, starting at bit `j`.
fn gather(chunk: &[u8], j: usize) -> u32 {
    (0..24).fold(0, |acc, t| {
        acc << 1 | bit_of(chunk, j + BLOCKS_PER_CHUNK * t)
    })
}

/// Writes block `j` of a chunk back to the bits [`gather`] took it from.
fn scatter(chunk: &mut [u8], j: usize, word: u32) {
    for t in 0..24 {
        let at = j + BLOCKS_PER_CHUNK * t;
        let mask = 1 << (7 - at % 8);
        let bit = (word >> (23 - t) & 1) as u8;
        chunk[at / 8] = chunk[at / 8] & !mask | bit << (7 - at % 8);
    }
}

/// Compresses each 504-bit chunk, padded with 8 zero bits, through the extractor and concatenates
/// the outputs into the factor.
fn extract_factor(
    response: &[u8],
    min_entropy_256: u8,
    seed: &[u8; SEED_LEN],
    factor: &mut [u8; FACTOR_LEN],
) -> Result<(), Error> {
    let extractor = Toeplitz::new(seed, chunk_min_entropy(min_entropy_256))?;
    let mut raw = Zeroizing::new([0u8; RAW_BLOCK]);
    let mut out = Zeroizing::new([0u8; MAX_OUTPUT]);
    let mut filled = 0;
    for chunk in response.chunks_exact(CHUNK_BYTES) {
        raw[..CHUNK_BYTES].copy_from_slice(chunk);
        extractor.extract(&raw, &mut out[..]);
        let take = extractor.output_len().min(FACTOR_LEN - filled);
        factor[filled..filled + take].copy_from_slice(&out[..take]);
        filled += take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};

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

    fn unit(i: usize) -> u16 {
        1 << (11 - i)
    }

    #[test]
    fn b_is_symmetric_and_its_own_inverse() {
        for (i, &row_i) in B.iter().enumerate() {
            for (j, &row_j) in B.iter().enumerate() {
                assert_eq!(row_i & unit(j) != 0, row_j & unit(i) != 0, "B[{i}][{j}]");
            }
            assert_eq!(times_b(times_b(unit(i))), unit(i), "row {i} of B²");
        }
    }

    /// Exhaustive: every non-zero codeword has weight at least 8, so the code fixes 3 errors.
    #[test]
    fn minimum_distance_is_8() {
        let lightest = (1..4096u16).map(|m| codeword(m).count_ones()).min();
        assert_eq!(lightest, Some(8));
    }

    /// Decoding depends only on the error pattern, so checking every pattern of weight 3 or less
    /// against a few messages covers all 2,325 patterns for every message.
    #[test]
    fn every_error_of_up_to_3_bits_is_corrected() {
        let patterns: Vec<u32> = (0u32..1 << 24).filter(|e| e.count_ones() <= 3).collect();
        assert_eq!(patterns.len(), 2325);
        for message in [0u16, 0x5a5, 0xfff, 0x123] {
            for &e in &patterns {
                assert_eq!(
                    decode(codeword(message) ^ e),
                    message,
                    "m={message:#x} e={e:#08x}"
                );
            }
        }
    }

    /// With 4 errors the nearest codeword is ambiguous, so decoding must not land on any other
    /// codeword: it returns the corrupted first half, never a wrong message that looks right.
    #[test]
    fn four_errors_are_never_silently_miscorrected() {
        for e in (0u32..1 << 24).filter(|e| e.count_ones() == 4) {
            let decoded = decode(e);
            assert!(
                decoded == (e >> 12) as u16,
                "e={e:#08x} decoded to {decoded:#x}"
            );
        }
    }

    fn response(chunks: u8, seed: u64) -> Vec<u8> {
        let mut r = vec![0u8; response_len(chunks)];
        TestRng(seed).fill(&mut r).unwrap();
        r
    }

    fn enrolled(e256: u8, response: &[u8]) -> (Vec<u8>, [u8; FACTOR_LEN]) {
        let chunks = chunks_needed(e256).unwrap();
        let mut helper = vec![0u8; helper_len(chunks)];
        let mut factor = [0u8; FACTOR_LEN];
        let seed = [0x3c; SEED_LEN];
        enroll(
            response,
            e256,
            &seed,
            &mut TestRng(9),
            &mut helper,
            &mut factor,
        )
        .unwrap();
        (helper, factor)
    }

    fn reproduced(response: &[u8], helper: &[u8]) -> [u8; FACTOR_LEN] {
        let mut factor = [0u8; FACTOR_LEN];
        reproduce(response, helper, &mut factor).unwrap();
        factor
    }

    #[test]
    fn chunks_follow_min_entropy() {
        assert_eq!(chunks_needed(255), Ok(3));
        assert_eq!(chunks_needed(243), Ok(3));
        assert_eq!(chunks_needed(230), Ok(4));
        assert_eq!(chunks_needed(204), Ok(18));
        assert_eq!(chunks_needed(179), Err(Error::SourceTooWeak));
    }

    #[test]
    fn noisy_readings_give_the_enrolled_factor() {
        let e256 = 230;
        let chunks = chunks_needed(e256).unwrap();
        let original = response(chunks, 1);
        let (helper, factor) = enrolled(e256, &original);
        assert_eq!(reproduced(&original, &helper), factor);

        // Flip 3 bits in every single block: the worst noise the code still corrects.
        let mut noisy = original.clone();
        let mut rng = TestRng(2);
        for chunk in noisy.chunks_exact_mut(CHUNK_BYTES) {
            for j in 0..BLOCKS_PER_CHUNK {
                let mut chosen = 0u32;
                while chosen.count_ones() < 3 {
                    let mut b = [0u8];
                    rng.fill(&mut b).unwrap();
                    chosen |= 1 << (b[0] % 24);
                }
                for t in (0..24).filter(|t| chosen >> t & 1 == 1) {
                    flip(chunk, j + BLOCKS_PER_CHUNK * t);
                }
            }
        }
        assert_ne!(noisy, original);
        assert_eq!(reproduced(&noisy, &helper), factor);
    }

    /// 63 neighbouring wrong bits, the shape of real PUF errors, land as exactly 3 per block.
    #[test]
    fn bursts_of_errors_are_spread_across_blocks() {
        let e256 = 230;
        let original = response(chunks_needed(e256).unwrap(), 7);
        let (helper, factor) = enrolled(e256, &original);
        let mut noisy = original.clone();
        for at in 8 * CHUNK_BYTES + 100..8 * CHUNK_BYTES + 163 {
            flip(&mut noisy, at);
        }
        assert_eq!(reproduced(&noisy, &helper), factor);
    }

    fn flip(bytes: &mut [u8], at: usize) {
        bytes[at / 8] ^= 1 << (7 - at % 8);
    }

    #[test]
    fn too_much_noise_or_another_chip_gives_a_different_factor_without_an_error() {
        let e256 = 230;
        let chunks = chunks_needed(e256).unwrap();
        let original = response(chunks, 3);
        let (helper, factor) = enrolled(e256, &original);

        // Four errors in one block are beyond the code.
        let mut noisy = original.clone();
        for t in 0..4 {
            flip(&mut noisy, 5 + BLOCKS_PER_CHUNK * t);
        }
        assert_ne!(reproduced(&noisy, &helper), factor);

        let other_chip = response(chunks, 4);
        assert_ne!(reproduced(&other_chip, &helper), factor);
    }

    #[test]
    fn doctored_helper_data_gives_a_different_factor_without_an_error() {
        let e256 = 230;
        let original = response(chunks_needed(e256).unwrap(), 5);
        let (helper, factor) = enrolled(e256, &original);
        let mut doctored = helper.clone();
        doctored[HELPER_HEADER + 30] ^= 0xf8;
        assert_ne!(reproduced(&original, &doctored), factor);
        let mut new_seed = helper.clone();
        new_seed[20] ^= 1;
        assert_ne!(reproduced(&original, &new_seed), factor);
    }

    #[test]
    fn malformed_helper_data_is_refused() {
        let e256 = 230;
        let original = response(chunks_needed(e256).unwrap(), 6);
        let (helper, _) = enrolled(e256, &original);
        let mut factor = [0u8; FACTOR_LEN];
        assert_eq!(
            reproduce(&original, &helper[..50], &mut factor),
            Err(Error::BadMagic)
        );
        assert_eq!(
            reproduce(&original[1..], &helper, &mut factor),
            Err(Error::BadLength)
        );
        let mut wrong_chunks = helper.clone();
        wrong_chunks[6] = 9;
        assert_eq!(
            reproduce(&original, &wrong_chunks, &mut factor),
            Err(Error::BadLength)
        );
    }
}
