//! Readout-window study: for each readout moment, how unique responses are across simulated chips
//! and how stable they are on one chip, including after a temperature change.
//!
//! The first command-line argument overrides the assumed jitter.

use puf_sim::{Device, JITTER, NODES, Network, Rng, TEMPERATURE_STRETCH, distance, run};

const DEVICES: usize = 20;
const CHALLENGES: usize = 16;
const TRIALS: usize = 10;

/// Readout moments, in nominal gate delays after the challenge is released.
const READOUTS: [f64; 11] = [0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 12.0, 16.0, 24.0, 32.0, 48.0];

fn main() {
    let jitter = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(JITTER);
    let mut rng = Rng(0x5eed_0fc4_a05e);
    let net = Network::new(&mut rng);
    let devices: Vec<Device> = (0..DEVICES).map(|_| Device::new(&mut rng)).collect();
    let challenges: Vec<u32> = (0..CHALLENGES).map(|_| rng.next_u64() as u32).collect();
    let mut noise = Rng(0xa11ce);
    let r = READOUTS.len();

    // enrolled[d][c][r]: the reference response, recorded once at the nominal temperature.
    let enrolled: Vec<Vec<Vec<u32>>> = devices
        .iter()
        .map(|dev| {
            challenges
                .iter()
                .map(|&c| run(&net, dev, c, &mut noise, jitter, 0.0, 1.0, &READOUTS))
                .collect()
        })
        .collect();

    let (mut unique, mut pairs) = (vec![0.0; r], 0.0);
    for a in 0..DEVICES {
        for b in a + 1..DEVICES {
            for (ea, eb) in enrolled[a].iter().zip(&enrolled[b]) {
                for t in 0..r {
                    unique[t] += distance(ea[t], eb[t]);
                }
                pairs += 1.0;
            }
        }
    }

    let mut same = vec![0.0; r];
    let mut hot_wall = vec![0.0; r];
    let mut hot_timed = vec![0.0; r];
    let mut stable_bits = vec![0.0; r];
    for (d, dev) in devices.iter().enumerate() {
        for (c, &challenge) in challenges.iter().enumerate() {
            let mut flipped = vec![0u32; r];
            for _ in 0..TRIALS {
                let again = run(
                    &net, dev, challenge, &mut noise, jitter, 0.0, 1.0, &READOUTS,
                );
                for t in 0..r {
                    same[t] += distance(enrolled[d][c][t], again[t]);
                    flipped[t] |= enrolled[d][c][t] ^ again[t];
                }
            }
            let wall = run(
                &net,
                dev,
                challenge,
                &mut noise,
                jitter,
                TEMPERATURE_STRETCH,
                1.0,
                &READOUTS,
            );
            let timed = run(
                &net,
                dev,
                challenge,
                &mut noise,
                jitter,
                TEMPERATURE_STRETCH,
                1.0 + TEMPERATURE_STRETCH,
                &READOUTS,
            );
            for t in 0..r {
                hot_wall[t] += distance(enrolled[d][c][t], wall[t]);
                hot_timed[t] += distance(enrolled[d][c][t], timed[t]);
                stable_bits[t] += 1.0 - flipped[t].count_ones() as f64 / NODES as f64;
            }
        }
    }

    let runs = (DEVICES * CHALLENGES) as f64;
    println!(
        "{DEVICES} chips, {CHALLENGES} challenges, {NODES} gates, jitter {:.1}%; \
         ideal: uniqueness 50%, errors 0%\n",
        jitter * 100.0
    );
    println!(
        "{:>8}  {:>10}  {:>10}  {:>13}  {:>13}  {:>7}",
        "readout", "uniqueness", "error", "error +20°C", "error +20°C", "stable"
    );
    println!(
        "{:>8}  {:>10}  {:>10}  {:>13}  {:>13}  {:>7}",
        "(delays)", "", "same temp", "wall clock", "on-chip clock", "bits"
    );
    for t in 0..r {
        println!(
            "{:>8}  {:>9.1}%  {:>9.1}%  {:>12.1}%  {:>12.1}%  {:>6.0}%",
            READOUTS[t],
            100.0 * unique[t] / pairs,
            100.0 * same[t] / (runs * TRIALS as f64),
            100.0 * hot_wall[t] / runs,
            100.0 * hot_timed[t] / runs,
            100.0 * stable_bits[t] / runs,
        );
    }
}
