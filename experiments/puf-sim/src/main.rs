//! Simulated chaotic PUF: a self-oscillating network of XOR and XNOR gates whose gate delays differ
//! slightly from chip to chip.
//!
//! A challenge sets the starting state; the response is the state read at a chosen moment. The
//! simulation measures, for each readout moment, how unique responses are across chips and how
//! stable they are on one chip, including after a temperature change.
//!
//! This is a model for choosing parameters before hardware exists. Every number in it rests on the
//! assumed physics below, not on silicon.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

const NODES: usize = 32;
const FAN_IN: usize = 3;
const DEVICES: usize = 20;
const CHALLENGES: usize = 16;
const TRIALS: usize = 10;

/// Readout moments, in nominal gate delays after the challenge is released.
const READOUTS: [f64; 11] = [0.5, 1.0, 2.0, 3.0, 5.0, 8.0, 12.0, 16.0, 24.0, 32.0, 48.0];

// Assumed physics, as fractions of a nominal gate delay (one standard deviation).
/// Chip-to-chip variation of each gate's delay.
const MANUFACTURING_SPREAD: f64 = 0.05;
/// Random timing noise added to every transition. The first command-line argument overrides it.
const JITTER: f64 = 0.005;
/// How much all delays stretch for a +20 °C change.
const TEMPERATURE_STRETCH: f64 = 0.04;
/// Gate-to-gate variation of that stretch.
const TEMPCO_SPREAD: f64 = 0.10;

/// SplitMix64, with Box–Muller for normal samples.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn uniform(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn normal(&mut self) -> f64 {
        let (u, v) = (self.uniform().max(f64::MIN_POSITIVE), self.uniform());
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

/// The circuit: identical on every chip, like one bitstream loaded onto many boards.
struct Network {
    inputs: [[usize; FAN_IN]; NODES],
    fan_out: Vec<Vec<usize>>,
}

impl Network {
    fn new(rng: &mut Rng) -> Self {
        let mut inputs = [[0; FAN_IN]; NODES];
        let mut fan_out = vec![Vec::new(); NODES];
        for (node, wires) in inputs.iter_mut().enumerate() {
            let mut chosen = 0;
            while chosen < FAN_IN {
                let source = (rng.next() % NODES as u64) as usize;
                if source != node && !wires[..chosen].contains(&source) {
                    wires[chosen] = source;
                    fan_out[source].push(node);
                    chosen += 1;
                }
            }
        }
        Self { inputs, fan_out }
    }

    /// Odd nodes are XNOR so that no all-zero or all-one state is frozen.
    fn target(&self, node: usize, state: &[bool; NODES]) -> bool {
        let parity = self.inputs[node]
            .iter()
            .fold(false, |acc, &i| acc ^ state[i]);
        parity ^ (node % 2 == 1)
    }
}

/// One chip: its own gate delays and temperature coefficients.
struct Device {
    delay: [f64; NODES],
    tempco: [f64; NODES],
}

impl Device {
    fn new(rng: &mut Rng) -> Self {
        Self {
            delay: std::array::from_fn(|_| 1.0 + MANUFACTURING_SPREAD * rng.normal()),
            tempco: std::array::from_fn(|_| 1.0 + TEMPCO_SPREAD * rng.normal()),
        }
    }
}

/// Runs one challenge on one chip and returns the state at every readout moment. `stretch` is the
/// temperature's effect on delays; `time_scale` multiplies the readout moments (1 for a wall
/// clock, or 1 + stretch for a clock made of the chip's own gates).
fn run(
    net: &Network,
    device: &Device,
    challenge: u32,
    noise: &mut Rng,
    jitter: f64,
    stretch: f64,
    time_scale: f64,
) -> Vec<u32> {
    let delay: [f64; NODES] =
        std::array::from_fn(|i| device.delay[i] * (1.0 + stretch * device.tempco[i]));
    let mut state: [bool; NODES] = std::array::from_fn(|i| challenge >> i & 1 == 1);
    let mut generation = [0u64; NODES];
    let mut pending = [false; NODES];
    let mut events = BinaryHeap::new();

    // Inertial delay: a gate flips one delay after its inputs call for it, unless they change back.
    let schedule = |node: usize,
                    now: f64,
                    state: &[bool; NODES],
                    pending: &mut [bool; NODES],
                    generation: &mut [u64; NODES],
                    events: &mut BinaryHeap<Reverse<(u64, usize, u64)>>,
                    noise: &mut Rng| {
        if net.target(node, state) == state[node] {
            if pending[node] {
                pending[node] = false;
                generation[node] += 1;
            }
        } else if !pending[node] {
            pending[node] = true;
            let at = now + delay[node] * (1.0 + jitter * noise.normal());
            events.push(Reverse((at.to_bits(), node, generation[node])));
        }
    };

    for node in 0..NODES {
        schedule(
            node,
            0.0,
            &state,
            &mut pending,
            &mut generation,
            &mut events,
            noise,
        );
    }
    let pack = |state: &[bool; NODES]| {
        state
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (b as u32) << i)
    };

    let mut responses = Vec::with_capacity(READOUTS.len());
    for readout in READOUTS.map(|t| t * time_scale) {
        while let Some(&Reverse((bits, node, stamp))) = events.peek() {
            let at = f64::from_bits(bits);
            if at > readout {
                break;
            }
            events.pop();
            if stamp != generation[node] {
                continue;
            }
            state[node] = !state[node];
            pending[node] = false;
            for &next in &net.fan_out[node] {
                schedule(
                    next,
                    at,
                    &state,
                    &mut pending,
                    &mut generation,
                    &mut events,
                    noise,
                );
            }
        }
        responses.push(pack(&state));
    }
    responses
}

fn distance(a: u32, b: u32) -> f64 {
    (a ^ b).count_ones() as f64 / NODES as f64
}

fn main() {
    let jitter = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(JITTER);
    let mut rng = Rng(0x5eed_0fc4_a05e);
    let net = Network::new(&mut rng);
    let devices: Vec<Device> = (0..DEVICES).map(|_| Device::new(&mut rng)).collect();
    let challenges: Vec<u32> = (0..CHALLENGES).map(|_| rng.next() as u32).collect();
    let mut noise = Rng(0xa11ce);
    let r = READOUTS.len();

    // enrolled[d][c][r]: the reference response, recorded once at the nominal temperature.
    let enrolled: Vec<Vec<Vec<u32>>> = devices
        .iter()
        .map(|dev| {
            challenges
                .iter()
                .map(|&c| run(&net, dev, c, &mut noise, jitter, 0.0, 1.0))
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
                let again = run(&net, dev, challenge, &mut noise, jitter, 0.0, 1.0);
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
            );
            let timed = run(
                &net,
                dev,
                challenge,
                &mut noise,
                jitter,
                TEMPERATURE_STRETCH,
                1.0 + TEMPERATURE_STRETCH,
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
