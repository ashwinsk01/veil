//! End-to-end check of the device factor on simulated chips. Each chip enrolls once through the
//! fuzzy extractor, then rebuilds its factor from fresh noisy readings, at the enrollment
//! temperature and 20 °C warmer. Every other chip then tries its luck with the first chip's helper
//! data.
//!
//! Enrollment keeps only bits that read the same in all enrollment reads, and every later reading
//! takes a majority vote over several reads. Both are standard ways to cut a PUF's error rate.
//!
//! Like the rest of this crate it is a model. The claimed min-entropy is an assumption, and a real
//! circuit needs enough gates to physically hold that much randomness.

use puf_sim::{Device, JITTER, NODES, Network, Rng, TEMPERATURE_STRETCH, run};
use veil_core::{Entropy, Error, FACTOR_LEN, SEED_LEN, fuzzy};

const CHIPS: usize = 10;
/// Independent oscillator networks per chip: 16 × 32 = 512 gates of physical randomness.
const NETWORKS: usize = 16;
/// Readout moment, in nominal gate delays: the onset of chaos.
const READOUT: f64 = 3.0;
const ENROLL_READS: usize = 9;
const REPRODUCE_READS: usize = 5;
const TRIALS: usize = 20;
/// Assumed min-entropy of each kept response bit, in 1/256ths of a bit.
const MIN_ENTROPY_256: u8 = 230;

struct SimEntropy(Rng);

impl Entropy for SimEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for byte in buf {
            *byte = self.0.next_u64() as u8;
        }
        Ok(())
    }
}

/// One chip: a delay set for each of the networks every chip shares.
struct Chip {
    networks: Vec<Device>,
}

/// Where each kept bit lives: network, challenge, and bit within the response.
#[derive(Clone, Copy)]
struct Position {
    network: usize,
    challenge: u32,
    bit: usize,
}

/// Reading conditions: the temperature's stretch of delays, and how readout time is measured.
#[derive(Clone, Copy)]
struct Conditions {
    stretch: f64,
    time_scale: f64,
}

const NOMINAL: Conditions = Conditions {
    stretch: 0.0,
    time_scale: 1.0,
};

struct Lab {
    nets: Vec<Network>,
    noise: Rng,
}

impl Lab {
    /// Majority over `reads` readings of one challenge on one network of a chip.
    fn read(
        &mut self,
        chip: &Chip,
        network: usize,
        challenge: u32,
        reads: usize,
        at: Conditions,
    ) -> (u32, u32) {
        let mut ones = [0usize; NODES];
        for _ in 0..reads {
            let state = run(
                &self.nets[network],
                &chip.networks[network],
                challenge,
                &mut self.noise,
                JITTER,
                at.stretch,
                at.time_scale,
                &[READOUT],
            )[0];
            for (bit, count) in ones.iter_mut().enumerate() {
                *count += (state >> bit & 1) as usize;
            }
        }
        let majority = (0..NODES).fold(0u32, |acc, b| acc | ((2 * ones[b] > reads) as u32) << b);
        let unanimous = (0..NODES).fold(0u32, |acc, b| {
            acc | ((ones[b] == 0 || ones[b] == reads) as u32) << b
        });
        (majority, unanimous)
    }

    /// Enrolls a chip: keeps bits that were unanimous across every enrollment read until there
    /// are enough for the extractor, and returns their positions and values.
    fn enroll(&mut self, chip: &Chip, bits_needed: usize) -> (Vec<Position>, Vec<bool>) {
        let (mut positions, mut values) = (Vec::new(), Vec::new());
        for challenge in 0u32.. {
            for network in 0..NETWORKS {
                let challenge = challenge.wrapping_mul(0x9e37_79b9) ^ network as u32;
                let (majority, unanimous) =
                    self.read(chip, network, challenge, ENROLL_READS, NOMINAL);
                for bit in (0..NODES).filter(|b| unanimous >> b & 1 == 1) {
                    positions.push(Position {
                        network,
                        challenge,
                        bit,
                    });
                    values.push(majority >> bit & 1 == 1);
                    if values.len() == bits_needed {
                        return (positions, values);
                    }
                }
            }
        }
        unreachable!()
    }

    /// Reads a chip at the enrolled positions, a majority vote per challenge.
    fn reproduce(&mut self, chip: &Chip, positions: &[Position], at: Conditions) -> Vec<bool> {
        let mut values = Vec::with_capacity(positions.len());
        let mut last: Option<(usize, u32, u32)> = None;
        for p in positions {
            let majority = match last {
                Some((network, challenge, majority))
                    if network == p.network && challenge == p.challenge =>
                {
                    majority
                }
                _ => {
                    self.read(chip, p.network, p.challenge, REPRODUCE_READS, at)
                        .0
                }
            };
            last = Some((p.network, p.challenge, majority));
            values.push(majority >> p.bit & 1 == 1);
        }
        values
    }
}

fn pack(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &b| acc << 1 | b as u8))
        .collect()
}

fn error_rate(a: &[bool], b: &[bool]) -> f64 {
    a.iter().zip(b).filter(|(x, y)| x != y).count() as f64 / a.len() as f64
}

fn main() {
    let mut rng = Rng(0xfa22_7e57);
    let nets: Vec<Network> = (0..NETWORKS).map(|_| Network::new(&mut rng)).collect();
    let chips: Vec<Chip> = (0..CHIPS)
        .map(|_| Chip {
            networks: (0..NETWORKS).map(|_| Device::new(&mut rng)).collect(),
        })
        .collect();
    let mut lab = Lab {
        nets,
        noise: Rng(0x0b5e_55ed),
    };
    let mut entropy = SimEntropy(Rng(0x5eed));

    let chunks = fuzzy::chunks_needed(MIN_ENTROPY_256).expect("claimed min-entropy is too low");
    let bits_needed = fuzzy::response_len(chunks) * 8;
    let warm = Conditions {
        stretch: TEMPERATURE_STRETCH,
        time_scale: 1.0 + TEMPERATURE_STRETCH,
    };
    let warm_wall = Conditions {
        stretch: TEMPERATURE_STRETCH,
        time_scale: 1.0,
    };
    let conditions = [
        ("same chip, same temperature", NOMINAL),
        ("same chip, +20 °C, on-chip clock", warm),
        ("same chip, +20 °C, wall clock", warm_wall),
    ];

    let mut matches = [0usize; 3];
    let mut errors = [0.0f64; 3];
    let (mut impostor_matches, mut impostor_errors, mut impostor_tries) = (0, 0.0, 0);
    for (c, chip) in chips.iter().enumerate() {
        let (positions, enrolled) = lab.enroll(chip, bits_needed);
        let mut seed = [0u8; SEED_LEN];
        entropy.fill(&mut seed).unwrap();
        let mut helper = vec![0u8; fuzzy::helper_len(chunks)];
        let mut factor = [0u8; FACTOR_LEN];
        fuzzy::enroll(
            &pack(&enrolled),
            MIN_ENTROPY_256,
            &seed,
            &mut entropy,
            &mut helper,
            &mut factor,
        )
        .unwrap();

        for (i, &(_, at)) in conditions.iter().enumerate() {
            for _ in 0..TRIALS {
                let reading = lab.reproduce(chip, &positions, at);
                errors[i] += error_rate(&enrolled, &reading);
                let mut again = [0u8; FACTOR_LEN];
                fuzzy::reproduce(&pack(&reading), &helper, &mut again).unwrap();
                matches[i] += (again == factor) as usize;
            }
        }
        for (o, other) in chips.iter().enumerate().filter(|&(o, _)| o != c) {
            let reading = lab.reproduce(other, &positions, NOMINAL);
            impostor_errors += error_rate(&enrolled, &reading);
            let mut theirs = [0u8; FACTOR_LEN];
            fuzzy::reproduce(&pack(&reading), &helper, &mut theirs).unwrap();
            impostor_matches += (theirs == factor) as usize;
            impostor_tries += 1;
            let _ = o;
        }
    }

    let security = fuzzy::chunk_security_bits(MIN_ENTROPY_256).unwrap();
    println!(
        "{CHIPS} chips of {NETWORKS} × {NODES} gates, readout at {READOUT} delays, jitter {:.1}%",
        JITTER * 100.0
    );
    println!(
        "{bits_needed} kept bits per chip in {chunks} chunks; each chunk's share of the factor within \
         2^-{security} of uniform, if each kept bit holds {:.2} bits of min-entropy\n",
        MIN_ENTROPY_256 as f64 / 256.0
    );
    println!(
        "{:<34}  {:>14}  {:>12}",
        "reading", "factor rebuilt", "bit errors"
    );
    let runs = CHIPS * TRIALS;
    for (i, (name, _)) in conditions.iter().enumerate() {
        println!(
            "{name:<34}  {:>9}/{runs:<4}  {:>11.2}%",
            matches[i],
            100.0 * errors[i] / runs as f64
        );
    }
    println!(
        "{:<34}  {:>9}/{impostor_tries:<4}  {:>11.2}%",
        "another chip, same helper data",
        impostor_matches,
        100.0 * impostor_errors / impostor_tries as f64
    );
}
