//! The shuffled keypad `veil write` types through. Characters sit in a fixed 10 × 10 grid whose
//! rows and columns are labelled with digits, and the labels reshuffle after every character. You
//! press a row digit, then a column digit, and both are uniformly random whatever you typed, so
//! someone who hears, logs or films your keys without also seeing the screen learns nothing.

use std::io::{self, Write};
use veil_core::{Entropy, Error, Mix, Ripple, Writer};
use zeroize::Zeroize;

/// What a cell of the grid types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    Char(u8),
    Delete,
    Pad,
}

/// Every printable ASCII character, once. The last row ends with Delete, Pad and three blanks.
const LAYOUT: [&str; 10] = [
    "abcdefghij",
    "klmnopqrst",
    "uvwxyzABCD",
    "EFGHIJKLMN",
    "OPQRSTUVWX",
    "YZ01234567",
    "89 .,!?-_@",
    "#$%&*()+=/",
    ":;'\"<>[]{}",
    "\\|`~^",
];

fn cell(row: usize, col: usize) -> Option<Cell> {
    match LAYOUT[row].as_bytes().get(col) {
        Some(&c) => Some(Cell::Char(c)),
        None if row == 9 && col == 5 => Some(Cell::Delete),
        None if row == 9 && col == 6 => Some(Cell::Pad),
        None => None,
    }
}

/// A uniformly random number below `n`, by rejection, so no value is favoured.
fn below<E: Entropy + ?Sized>(rng: &mut E, n: u8) -> Result<u8, Error> {
    let limit = 256 - 256 % n as u16;
    loop {
        let mut byte = [0u8];
        rng.fill(&mut byte)?;
        if (byte[0] as u16) < limit {
            return Ok(byte[0] % n);
        }
    }
}

/// The digits labelling each row and column right now.
pub struct Keypad {
    rows: [u8; 10],
    cols: [u8; 10],
}

impl Keypad {
    pub fn new() -> Self {
        Self {
            rows: core::array::from_fn(|i| i as u8),
            cols: core::array::from_fn(|i| i as u8),
        }
    }

    /// Draws fresh, independent, uniformly random labellings (Fisher–Yates).
    pub fn shuffle<E: Entropy + ?Sized>(&mut self, rng: &mut E) -> Result<(), Error> {
        for labels in [&mut self.rows, &mut self.cols] {
            for (i, label) in labels.iter_mut().enumerate() {
                *label = i as u8;
            }
            for i in (1..10).rev() {
                let j = below(rng, i as u8 + 1)? as usize;
                labels.swap(i, j);
            }
        }
        Ok(())
    }

    /// The cell whose row is labelled `row_digit` and whose column is labelled `col_digit`.
    /// Every label is compared, so the time taken doesn't depend on where the cell is.
    pub fn select(&self, row_digit: u8, col_digit: u8) -> Option<Cell> {
        let find = |labels: &[u8; 10], digit: u8| {
            labels.iter().enumerate().fold(0, |at, (i, &d)| {
                at | (i & 0usize.wrapping_sub((d == digit) as usize))
            })
        };
        cell(find(&self.rows, row_digit), find(&self.cols, col_digit))
    }

    /// The whole screen: the grid with its current labels, how much has been written, and how to
    /// type. Nothing typed is ever shown.
    pub fn render(&self, written: usize, k: u8, n: u8, column_next: bool, color: bool) -> String {
        let paint = |code: &str, text: &str| {
            if color {
                format!("\x1b[{code}m{text}\x1b[0m")
            } else {
                text.to_owned()
            }
        };
        let label = |digit: u8| paint("1;36", &digit.to_string());
        let mut out = String::from("\x1b[H\x1b[2J\n");
        out += &format!(
            "  {}   {k} of {n} · {written} characters written · nothing you type is shown\n\n",
            paint("1;36", "⟐ VEIL · WRITE ⟐")
        );
        out += "      ";
        for &digit in &self.cols {
            out += &format!("{}  ", label(digit));
        }
        out += "\n";
        out += &format!("    {}\n", paint("2", &format!("┌{}┐", "─".repeat(31))));
        for (r, &digit) in self.rows.iter().enumerate() {
            out += &format!("  {} {} ", label(digit), paint("2", "│"));
            for c in 0..10 {
                let shown = match cell(r, c) {
                    Some(Cell::Char(b' ')) => paint("33", "␣"),
                    Some(Cell::Char(ch)) => (ch as char).to_string(),
                    Some(Cell::Delete) => paint("33", "⌫"),
                    Some(Cell::Pad) => paint("33", "·"),
                    None => " ".to_owned(),
                };
                out += &format!("{shown}  ");
            }
            out += &format!("{}\n", paint("2", "│"));
        }
        out += &format!("    {}\n\n", paint("2", &format!("└{}┘", "─".repeat(31))));
        out += if column_next {
            "  row chosen. now press its column's digit.\n"
        } else {
            "  find your character, press its row's digit, then its column's digit.\n"
        };
        out +=
            "  the digits reshuffle after every character, so the keys you press reveal nothing.\n";
        out += &format!(
            "  {} deletes · {} types nothing · enter finishes · ctrl-c cancels\n",
            paint("33", "⌫"),
            paint("33", "·")
        );
        out
    }
}

impl Default for Keypad {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Keypad {
    fn drop(&mut self) {
        self.rows.zeroize();
        self.cols.zeroize();
    }
}

/// Switches to the terminal's alternate screen, so the keypad never lands in scrollback.
pub struct AltScreen;

impl AltScreen {
    pub fn enter() -> io::Result<Self> {
        let mut err = io::stderr();
        err.write_all(b"\x1b[?1049h")?;
        err.flush()?;
        Ok(Self)
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        let mut err = io::stderr();
        let _ = err.write_all(b"\x1b[?1049l");
        let _ = err.flush();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Finished,
    Cancelled,
}

enum Key {
    Digit(u8),
    Enter,
    Cancel,
}

/// Reads keys until a digit, Enter, Ctrl-C or the end of input. Each digit's timing and value
/// ripple into the randomness for this character; other keys are ignored.
fn next_key(
    keys: &mut dyn FnMut() -> io::Result<Option<(u64, u8)>>,
    ripple: &mut Ripple,
) -> Result<Key, String> {
    loop {
        match keys().map_err(|e| format!("keyboard: {e}"))? {
            None | Some((_, 3)) => return Ok(Key::Cancel),
            Some((_, b'\r' | b'\n')) => return Ok(Key::Enter),
            Some((nanos, digit @ b'0'..=b'9')) => {
                let mut event = [0u8; 9];
                event[..8].copy_from_slice(&nanos.to_le_bytes());
                event[8] = digit;
                ripple.stir(&event);
                event.zeroize();
                return Ok(Key::Digit(digit - b'0'));
            }
            Some(_) => {}
        }
    }
}

/// Runs the typing session. Before every character the keypad reshuffles and is drawn; then a row
/// digit and a column digit pick a cell, and a character is split into the writer at once.
pub fn session(
    keys: &mut dyn FnMut() -> io::Result<Option<(u64, u8)>>,
    rng: &mut dyn Entropy,
    writer: &mut Writer<'_, '_>,
    draw: &mut dyn FnMut(&Keypad, usize, bool) -> io::Result<()>,
) -> Result<Outcome, String> {
    let mut keypad = Keypad::new();
    let screen = |e: io::Error| format!("screen: {e}");
    loop {
        keypad.shuffle(rng).map_err(|e| e.to_string())?;
        draw(&keypad, writer.len(), false).map_err(screen)?;
        let mut ripple = Ripple::new();
        let row = match next_key(keys, &mut ripple)? {
            Key::Digit(d) => d,
            Key::Enter => return Ok(Outcome::Finished),
            Key::Cancel => return Ok(Outcome::Cancelled),
        };
        draw(&keypad, writer.len(), true).map_err(screen)?;
        let col = match next_key(keys, &mut ripple)? {
            Key::Digit(d) => d,
            Key::Enter => return Ok(Outcome::Finished),
            Key::Cancel => return Ok(Outcome::Cancelled),
        };
        match keypad.select(row, col) {
            Some(Cell::Char(mut ch)) => {
                let pushed = writer.push(ch, &mut Mix(&mut *rng, ripple));
                ch.zeroize();
                pushed.map_err(|e| e.to_string())?;
            }
            Some(Cell::Delete) => writer.pop(),
            Some(Cell::Pad) | None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use veil_core::{Secret, ShareView, combine, share_len};

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

    fn position(target: Cell) -> (usize, usize) {
        (0..100)
            .map(|i| (i / 10, i % 10))
            .find(|&(r, c)| cell(r, c) == Some(target))
            .expect("every character has a cell")
    }

    #[test]
    fn grid_holds_every_printable_character_once() {
        let mut seen = [0u8; 128];
        for r in 0..10 {
            for c in 0..10 {
                if let Some(Cell::Char(ch)) = cell(r, c) {
                    seen[ch as usize] += 1;
                }
            }
        }
        assert!((32..127).all(|ch| seen[ch] == 1));
        assert_eq!(seen.iter().map(|&n| n as usize).sum::<usize>(), 95);
        assert_eq!(cell(9, 5), Some(Cell::Delete));
        assert_eq!(cell(9, 6), Some(Cell::Pad));
    }

    /// Exhaustive over every byte the generator could give: each value below n comes out equally
    /// often, so the labels carry no bias.
    #[test]
    fn below_favours_no_value() {
        struct Every(u16);
        impl Entropy for Every {
            fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
                for byte in buf {
                    *byte = self.0 as u8;
                    self.0 += 1;
                }
                Ok(())
            }
        }
        for n in 1..=10u8 {
            let limit = 256 - 256 % n as u16;
            let mut counts = [0u16; 10];
            let mut source = Every(0);
            while source.0 < limit {
                counts[below(&mut source, n).unwrap() as usize] += 1;
            }
            assert!(
                counts[..n as usize].iter().all(|&c| c == limit / n as u16),
                "n={n}"
            );
        }
    }

    #[test]
    fn shuffles_are_permutations_and_select_finds_the_cell() {
        let mut keypad = Keypad::new();
        let mut rng = TestRng(1);
        for _ in 0..50 {
            keypad.shuffle(&mut rng).unwrap();
            let mut rows = keypad.rows;
            rows.sort();
            assert_eq!(rows, core::array::from_fn(|i| i as u8));
            let (r, c) = position(Cell::Char(b'q'));
            assert_eq!(
                keypad.select(keypad.rows[r], keypad.cols[c]),
                Some(Cell::Char(b'q'))
            );
        }
    }

    enum Act {
        Type(u8),
        Delete,
        Pad,
        Enter,
        Cancel,
    }

    /// A simulated user who reads each freshly drawn keypad and presses the digits for the next
    /// action, exactly as a person would.
    fn type_through(acts: Vec<Act>, k: u8, n: u8) -> (Outcome, Vec<Vec<u8>>, usize) {
        let mut shares = vec![vec![0; share_len(n)]; n as usize];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        let mut rng = TestRng(7);
        let mut writer = Writer::new(k, n, &mut refs).unwrap();
        let screen = RefCell::new(([0u8; 10], [0u8; 10]));
        let mut acts = VecDeque::from(acts);
        let mut pending: VecDeque<u8> = VecDeque::new();
        let mut draw = |pad: &Keypad, _written: usize, column_next: bool| -> io::Result<()> {
            if !column_next {
                *screen.borrow_mut() = (pad.rows, pad.cols);
            }
            Ok(())
        };
        let mut keys = || -> io::Result<Option<(u64, u8)>> {
            if pending.is_empty() {
                let (rows, cols) = *screen.borrow();
                let target = match acts.pop_front() {
                    Some(Act::Type(ch)) => Cell::Char(ch),
                    Some(Act::Delete) => Cell::Delete,
                    Some(Act::Pad) => Cell::Pad,
                    Some(Act::Enter) | None => return Ok(Some((1_000, b'\r'))),
                    Some(Act::Cancel) => return Ok(Some((1_000, 3))),
                };
                let (r, c) = position(target);
                pending.push_back(b'0' + rows[r]);
                pending.push_back(b'x');
                pending.push_back(b'0' + cols[c]);
            }
            Ok(pending.pop_front().map(|key| (1_000, key)))
        };
        let outcome = session(&mut keys, &mut rng, &mut writer, &mut draw).unwrap();
        let written = writer.len();
        if outcome == Outcome::Finished {
            writer.finish(&mut rng).unwrap();
        }
        (outcome, shares, written)
    }

    fn rebuild(shares: &[Vec<u8>]) -> Vec<u8> {
        let views: Vec<ShareView<'_>> = shares
            .iter()
            .map(|s| ShareView::parse(s).unwrap())
            .collect();
        let mut out = Secret::new();
        combine(&views, &mut out).unwrap();
        out.file().unwrap().to_vec()
    }

    #[test]
    fn a_user_reading_the_screen_types_the_text() {
        let text = b"Tr0ub4dor & 3 horses! ~ \\ \"quoted\"";
        let mut acts: Vec<Act> = text.iter().map(|&b| Act::Type(b)).collect();
        acts.push(Act::Enter);
        let (outcome, shares, written) = type_through(acts, 3, 5);
        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(written, text.len());
        assert_eq!(rebuild(&shares[1..4]), text);
    }

    #[test]
    fn delete_and_pad_cells_edit_without_typing() {
        let acts = vec![
            Act::Type(b'c'),
            Act::Pad,
            Act::Type(b'a'),
            Act::Type(b'x'),
            Act::Delete,
            Act::Pad,
            Act::Type(b't'),
            Act::Enter,
        ];
        let (_, shares, _) = type_through(acts, 2, 3);
        assert_eq!(rebuild(&shares[..2]), b"cat");
    }

    #[test]
    fn ctrl_c_cancels() {
        let acts = vec![Act::Type(b's'), Act::Type(b'e'), Act::Cancel];
        let (outcome, _, written) = type_through(acts, 3, 5);
        assert_eq!(outcome, Outcome::Cancelled);
        assert_eq!(written, 2);
    }
}
