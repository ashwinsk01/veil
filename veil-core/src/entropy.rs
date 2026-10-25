//! Hardware randomness: health-tested, extracted, and mixed with a second source.
//!
//! A raw noise source goes through the continuous health tests of NIST SP 800-90B §4.4, then the
//! Toeplitz extractor. The result is XORed with another source, so the output is uniform whenever
//! either one is: adding a hardware source can never make the randomness worse.

use crate::extract::{RAW_BLOCK, Toeplitz};
use crate::{Entropy, Error, mac};
use zeroize::{Zeroize, Zeroizing};

/// Samples per adaptive proportion test window, for byte-sized samples.
pub const APT_WINDOW: u32 = 512;

/// Samples checked and discarded when a source starts.
pub const STARTUP_SAMPLES: usize = 1024;

/// A raw noise source: a hardware device, or a capture of one.
pub trait RawSource {
    fn read_raw(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// SP 800-90B's repetition count and adaptive proportion tests. They catch a source that has stuck
/// or lost most of its entropy. They cannot tell real noise from a clever fake.
pub struct HealthTests {
    rct_cutoff: u32,
    apt_cutoff: u32,
    last: u8,
    run: u32,
    apt_first: u8,
    apt_count: u32,
    apt_seen: u32,
}

impl HealthTests {
    /// A source fails when one value repeats `rct_cutoff` times in a row, or when the first value of
    /// a 512-sample window appears `apt_cutoff` times within it.
    pub fn new(rct_cutoff: u32, apt_cutoff: u32) -> Self {
        Self {
            rct_cutoff,
            apt_cutoff,
            last: 0,
            run: 0,
            apt_first: 0,
            apt_count: 0,
            apt_seen: 0,
        }
    }

    pub fn check(&mut self, sample: u8) -> Result<(), Error> {
        let repeat = (self.run > 0 && sample == self.last) as u32;
        self.run = repeat * self.run + 1;
        self.last = sample;
        if self.run >= self.rct_cutoff {
            return Err(Error::HealthTestFailed);
        }

        if self.apt_seen == 0 {
            self.apt_first = sample;
            self.apt_count = 0;
        }
        self.apt_count += (sample == self.apt_first) as u32;
        self.apt_seen = (self.apt_seen + 1) % APT_WINDOW;
        if self.apt_count >= self.apt_cutoff {
            return Err(Error::HealthTestFailed);
        }
        Ok(())
    }
}

/// A raw source behind health tests and an extractor: an [`Entropy`] source of nearly uniform bytes.
pub struct Conditioned<R: RawSource> {
    raw: R,
    health: HealthTests,
    extractor: Toeplitz,
    out: [u8; crate::extract::MAX_OUTPUT],
    available: usize,
    blocks: u64,
}

impl<R: RawSource> Conditioned<R> {
    /// Runs the start-up test: the first 1024 samples are checked, then thrown away.
    pub fn new(raw: R, health: HealthTests, extractor: Toeplitz) -> Result<Self, Error> {
        let mut source = Self {
            raw,
            health,
            extractor,
            out: [0; crate::extract::MAX_OUTPUT],
            available: 0,
            blocks: 0,
        };
        let mut block = Zeroizing::new([0u8; RAW_BLOCK]);
        for _ in 0..STARTUP_SAMPLES / RAW_BLOCK {
            source.read_checked(&mut block)?;
        }
        Ok(source)
    }

    /// Raw blocks extracted so far.
    pub fn blocks_used(&self) -> u64 {
        self.blocks
    }

    /// Each block's output is within 2^-security_bits of uniform.
    pub fn security_bits(&self) -> u32 {
        self.extractor.security_bits()
    }

    fn read_checked(&mut self, block: &mut [u8; RAW_BLOCK]) -> Result<(), Error> {
        self.raw.read_raw(block)?;
        for &sample in block.iter() {
            self.health.check(sample)?;
        }
        Ok(())
    }

    fn refill(&mut self) -> Result<(), Error> {
        let mut block = Zeroizing::new([0u8; RAW_BLOCK]);
        self.read_checked(&mut block)?;
        self.extractor.extract(&block, &mut self.out);
        self.available = self.extractor.output_len();
        self.blocks += 1;
        Ok(())
    }
}

impl<R: RawSource> Entropy for Conditioned<R> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for byte in buf {
            if self.available == 0 {
                self.refill()?;
            }
            self.available -= 1;
            *byte = self.out[self.available];
            self.out[self.available] = 0;
        }
        Ok(())
    }
}

impl<R: RawSource> Drop for Conditioned<R> {
    fn drop(&mut self) {
        self.out.zeroize();
    }
}

/// The XOR of two independent sources: uniform whenever either one is.
pub struct Mix<A, B>(pub A, pub B);

impl<A: Entropy, B: Entropy> Entropy for Mix<A, B> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.0.fill(buf)?;
        let mut other = Zeroizing::new([0u8; 64]);
        for chunk in buf.chunks_mut(64) {
            let other = &mut other[..chunk.len()];
            self.1.fill(other)?;
            mac::xor_into(chunk, other);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::SEED_LEN;
    use crate::{MAX_FILE, Secret, ShareView, combine, share_len, split};
    use std::{vec, vec::Vec};

    /// Replays a fixed byte string as a raw source, then reports exhaustion.
    struct Replay {
        bytes: Vec<u8>,
        at: usize,
    }

    impl RawSource for Replay {
        fn read_raw(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            let end = self.at + buf.len();
            let chunk = self.bytes.get(self.at..end).ok_or(Error::Entropy)?;
            buf.copy_from_slice(chunk);
            self.at = end;
            Ok(())
        }
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
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

    /// Cutoffs for 7.5 bits of min-entropy per byte at a 2^-30 false alarm rate.
    fn health() -> HealthTests {
        HealthTests::new(5, 18)
    }

    fn conditioned(bytes: Vec<u8>) -> Result<Conditioned<Replay>, Error> {
        let extractor = Toeplitz::new(&[0xa5; SEED_LEN], 480).unwrap();
        Conditioned::new(Replay { bytes, at: 0 }, health(), extractor)
    }

    struct Zeros;

    impl Entropy for Zeros {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            buf.fill(0);
            Ok(())
        }
    }

    #[test]
    fn stuck_source_fails_at_start_up() {
        assert!(matches!(
            conditioned(vec![0x42; 100_000]),
            Err(Error::HealthTestFailed)
        ));
    }

    #[test]
    fn source_that_dies_midway_stops_everything() {
        let mut bytes = noise(5_000, 1);
        bytes.extend([0u8; 5_000]);
        let mut source = conditioned(bytes).unwrap();
        let mut buf = vec![0u8; 2_000];
        assert!(matches!(
            source.fill(&mut buf),
            Err(Error::HealthTestFailed)
        ));
    }

    /// Two alternating values never repeat back to back, so only the proportion test sees it.
    #[test]
    fn two_value_source_fails_the_proportion_test() {
        let bytes: Vec<u8> = (0..10_000).map(|i| (i % 2) as u8).collect();
        assert!(matches!(conditioned(bytes), Err(Error::HealthTestFailed)));
    }

    #[test]
    fn healthy_source_passes_and_extracts() {
        let mut source = conditioned(noise(100_000, 2)).unwrap();
        let mut buf = vec![0u8; 4_096];
        source.fill(&mut buf).unwrap();
        assert_eq!(source.blocks_used(), 256);
        assert_ne!(buf, vec![0u8; 4_096]);
    }

    #[test]
    fn exhausted_source_is_an_error() {
        let mut source = conditioned(noise(2_000, 3)).unwrap();
        let mut buf = vec![0u8; 1_000];
        assert!(matches!(source.fill(&mut buf), Err(Error::Entropy)));
    }

    #[test]
    fn mixing_in_a_dead_source_changes_nothing() {
        struct Counter(u8);
        impl Entropy for Counter {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
                for b in buf {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        let (mut alone, mut mixed) = ([0u8; 300], [0u8; 300]);
        Counter(0).fill(&mut alone).unwrap();
        Mix(Counter(0), Zeros).fill(&mut mixed).unwrap();
        assert_eq!(alone, mixed);
    }

    #[test]
    fn hardware_randomness_drives_a_full_split() {
        let file = vec![0x37; MAX_FILE];
        let mut secret = Secret::new();
        secret.load(&file).unwrap();
        let mut rng = Mix(Zeros, conditioned(noise(200_000, 4)).unwrap());
        let mut shares = vec![vec![0; share_len(5)]; 5];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        split(&secret, 3, 5, &mut rng, &mut refs).unwrap();
        assert!(rng.1.blocks_used() > 1_000);

        let views: Vec<ShareView<'_>> = shares[1..4]
            .iter()
            .map(|s| ShareView::parse(s).unwrap())
            .collect();
        let mut out = Secret::new();
        combine(&views, &mut out).unwrap();
        assert_eq!(out.file().unwrap(), &file[..]);
    }
}
