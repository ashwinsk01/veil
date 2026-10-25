//! Model of a chaotic PUF: a self-oscillating network of XOR and XNOR gates whose gate delays
//! differ slightly from chip to chip. A challenge sets the starting state; the response is the
//! state read at a chosen moment.
//!
//! This is a model for choosing parameters before hardware exists. Every number it produces rests
//! on the assumed physics below, not on silicon.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

pub const NODES: usize = 32;
const FAN_IN: usize = 3;

// Assumed physics, as fractions of a nominal gate delay (one standard deviation).
/// Chip-to-chip variation of each gate's delay.
const MANUFACTURING_SPREAD: f64 = 0.05;
/// Random timing noise added to every transition.
pub const JITTER: f64 = 0.005;
/// How much all delays stretch for a +20 °C change.
pub const TEMPERATURE_STRETCH: f64 = 0.04;
/// Gate-to-gate variation of that stretch.
const TEMPCO_SPREAD: f64 = 0.10;

/// SplitMix64, with Box–Muller for normal samples.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn normal(&mut self) -> f64 {
        let (u, v) = (self.uniform().max(f64::MIN_POSITIVE), self.uniform());
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

/// The circuit: identical on every chip, like one bitstream loaded onto many boards.
pub struct Network {
    inputs: [[usize; FAN_IN]; NODES],
    fan_out: Vec<Vec<usize>>,
}

impl Network {
    pub fn new(rng: &mut Rng) -> Self {
        let mut inputs = [[0; FAN_IN]; NODES];
        let mut fan_out = vec![Vec::new(); NODES];
        for (node, wires) in inputs.iter_mut().enumerate() {
            let mut chosen = 0;
            while chosen < FAN_IN {
                let source = (rng.next_u64() % NODES as u64) as usize;
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
pub struct Device {
    delay: [f64; NODES],
    tempco: [f64; NODES],
}

impl Device {
    pub fn new(rng: &mut Rng) -> Self {
        Self {
            delay: std::array::from_fn(|_| 1.0 + MANUFACTURING_SPREAD * rng.normal()),
            tempco: std::array::from_fn(|_| 1.0 + TEMPCO_SPREAD * rng.normal()),
        }
    }
}

/// Runs one challenge on one chip and returns the state at each readout moment, in nominal gate
/// delays. `stretch` is the temperature's effect on delays; `time_scale` multiplies the readout
/// moments (1 for a wall clock, or 1 + stretch for a clock made of the chip's own gates).
#[allow(clippy::too_many_arguments)]
pub fn run(
    net: &Network,
    device: &Device,
    challenge: u32,
    noise: &mut Rng,
    jitter: f64,
    stretch: f64,
    time_scale: f64,
    readouts: &[f64],
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

    let mut responses = Vec::with_capacity(readouts.len());
    for readout in readouts.iter().map(|t| t * time_scale) {
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

/// Fraction of response bits that differ.
pub fn distance(a: u32, b: u32) -> f64 {
    (a ^ b).count_ones() as f64 / NODES as f64
}
