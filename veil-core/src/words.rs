//! Words: how a 36-byte factor is spelled so a person can keep it, and read back from what they
//! type.
//!
//! A factor has two spellings, and recovery tells them apart by the number of words:
//!
//! - **English**: 27 words from the BIP-39 English list (CC0, via the rust-bip39 crate), 11 bits
//!   each.
//! - **Polyglot**: 23 words from four lists of 2,048 in four scripts, English, Tamil, Hindi and
//!   Russian, 13 bits each. A word's script says which list it is from.
//!
//! Either way the factor's 288 bits come first and the top bits of its CRC-16 fill the rest, so
//! typos are caught before recovery and say nothing about the key. English and Russian words are
//! identified by their first four letters; Tamil and Hindi words are typed whole. Tamil, Hindi and
//! Russian words match after folding together the letters people confuse (see [`Folded`]), and no
//! list holds two words that differ only in those.

use crate::{Error, FACTOR_LEN};
use zeroize::{Zeroize, Zeroizing};

/// Words in the longer spelling.
const MAX_WORDS: usize = 27;
const LIST_LEN: usize = 2048;

const ENGLISH: usize = 0;
const TAMIL: usize = 1;
const HINDI: usize = 2;
const RUSSIAN: usize = 3;

/// One word per line, in index order. Each list's index range follows the one before.
static LISTS: [&str; 4] = [
    include_str!("words/english.txt"),
    include_str!("words/tamil.txt"),
    include_str!("words/hindi.txt"),
    include_str!("words/russian.txt"),
];

/// How a factor is spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spelling {
    /// 27 words from the BIP-39 English list.
    English,
    /// 23 words from the English, Tamil, Hindi and Russian lists together.
    Polyglot,
}

impl Spelling {
    /// How many words spell a factor.
    pub const fn word_count(self) -> usize {
        match self {
            Spelling::English => 27,
            Spelling::Polyglot => 23,
        }
    }

    /// Bits each word carries: it is one of 2,048 words, or one of 8,192.
    const fn bits(self) -> usize {
        match self {
            Spelling::English => 11,
            Spelling::Polyglot => 13,
        }
    }
}

/// A factor spelled as indices for [`word`]. Zeroed when dropped.
pub struct Phrase {
    indices: [u16; MAX_WORDS],
    len: usize,
}

impl Phrase {
    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.len]
    }
}

impl Drop for Phrase {
    fn drop(&mut self) {
        self.indices.zeroize();
    }
}

/// Spells a factor: its bits most significant first, then the top bits of its CRC-16, cut into
/// words of 11 or 13 bits.
pub fn factor_to_words(factor: &[u8; FACTOR_LEN], spelling: Spelling) -> Phrase {
    let mut bits = Zeroizing::new([0u8; FACTOR_LEN + 2]);
    bits[..FACTOR_LEN].copy_from_slice(factor);
    bits[FACTOR_LEN..].copy_from_slice(&crc16(factor).to_be_bytes());
    let width = spelling.bits();
    let mut phrase = Phrase {
        indices: [0; MAX_WORDS],
        len: spelling.word_count(),
    };
    for (w, index) in phrase.indices[..phrase.len].iter_mut().enumerate() {
        *index = (0..width).fold(0u16, |acc, b| acc << 1 | bit(&bits[..], width * w + b));
    }
    phrase
}

/// The word at `index`. 0 to 2,047 are the English list, then Tamil, Hindi and Russian follow with
/// 2,048 each.
pub fn word(index: u16) -> &'static str {
    let (list, at) = (index as usize / LIST_LEN, index as usize % LIST_LEN);
    LISTS
        .get(list)
        .and_then(|words| words.lines().nth(at))
        .unwrap_or_default()
}

/// Decodes typed words back into a factor, in either spelling. Case is ignored, English and Russian
/// words may be shortened to their first four letters, and letters people confuse count as one.
/// Typos are caught by the checksum, which says nothing about the key.
pub fn words_to_factor(text: &str) -> Result<[u8; FACTOR_LEN], Error> {
    let spelling = match text.split_whitespace().count() {
        27 => Spelling::English,
        23 => Spelling::Polyglot,
        _ => return Err(Error::BadWords),
    };
    let mut indices = Zeroizing::new([0u16; MAX_WORDS]);
    for (index, token) in indices.iter_mut().zip(text.split_whitespace()) {
        *index = lookup(token, spelling).ok_or(Error::BadWords)?;
    }
    let (width, count) = (spelling.bits(), spelling.word_count());
    let mut bits = Zeroizing::new([0u8; FACTOR_LEN + 2]);
    for (w, &index) in indices[..count].iter().enumerate() {
        for b in 0..width {
            let at = width * w + b;
            bits[at / 8] |= ((index >> (width - 1 - b) & 1) as u8) << (7 - at % 8);
        }
    }
    let mut factor = [0u8; FACTOR_LEN];
    factor.copy_from_slice(&bits[..FACTOR_LEN]);
    let unused = 16 - (width * count - 8 * FACTOR_LEN);
    let checksum = u16::from_be_bytes([bits[FACTOR_LEN], bits[FACTOR_LEN + 1]]);
    if checksum >> unused != crc16(&factor) >> unused {
        factor.zeroize();
        return Err(Error::BadWords);
    }
    Ok(factor)
}

/// The index of `token` among the words `spelling` uses. Its first letter's script picks the list.
fn lookup(token: &str, spelling: Spelling) -> Option<u16> {
    let list = match token.chars().next()? {
        'a'..='z' | 'A'..='Z' => return english(token),
        _ if spelling == Spelling::English => return None,
        '\u{b80}'..='\u{bff}' => TAMIL,
        '\u{900}'..='\u{97f}' => HINDI,
        '\u{400}'..='\u{4ff}' => RUSSIAN,
        _ => return None,
    };
    let typed = Folded::new(token)?;
    let shortened = list == RUSSIAN && typed.len >= 4;
    let mut found = None;
    for (i, candidate) in LISTS[list].lines().enumerate() {
        let matches = Folded::new(candidate).is_some_and(|c| {
            c == typed || (shortened && c.as_slice().starts_with(typed.as_slice()))
        });
        if matches {
            found = Some((list * LIST_LEN + i) as u16);
        }
    }
    found
}

fn english(token: &str) -> Option<u16> {
    let mut found = None;
    for (i, candidate) in LISTS[ENGLISH].lines().enumerate() {
        let shortened = token.len() >= 4
            && candidate.len() > token.len()
            && candidate.as_bytes()[..token.len()].eq_ignore_ascii_case(token.as_bytes());
        if candidate.eq_ignore_ascii_case(token) || shortened {
            found = Some((ENGLISH * LIST_LEN + i) as u16);
        }
    }
    found
}

/// Longest folded word that can match. List words are at most 8 letters, and a Tamil vowel sign
/// written in two parts counts as two.
const FOLDED_MAX: usize = 24;

/// क़ ख़ ग़ ज़ ड़ ढ़ फ़ य़ written as one code point each, without their nukta.
const NUKTA_BASES: [char; 8] = ['क', 'ख', 'ग', 'ज', 'ड', 'ढ', 'फ', 'य'];

/// A Tamil, Hindi or Russian word in the one form words are matched on, however it was typed:
///
/// - Tamil: ல ள ழ as one, ர ற as one, ண ந ன as one, and each two-part vowel sign as its parts.
/// - Hindi: the nukta dropped, chandrabindu as anusvara, a half nasal before a consonant as
///   anusvara (हिन्दी and हिंदी), long and short i and u as one, and ष as श.
/// - Russian: lowercase, ё as е, and й typed as и plus a breve as й.
///
/// Zero-width joiners are ignored. Zeroed when dropped, since typed words are secret.
struct Folded {
    chars: [char; FOLDED_MAX],
    len: usize,
}

impl Folded {
    fn new(word: &str) -> Option<Self> {
        let mut folded = Folded {
            chars: ['\0'; FOLDED_MAX],
            len: 0,
        };
        for c in word.chars() {
            let (first, second) = match c {
                '\u{200c}' | '\u{200d}' | '\u{93c}' | '\u{308}' => continue,
                '\u{306}' if folded.last() == Some('и') => {
                    folded.chars[folded.len - 1] = 'й';
                    continue;
                }
                // Tamil
                '\u{bca}' => ('\u{bc6}', Some('\u{bbe}')),
                '\u{bcb}' => ('\u{bc7}', Some('\u{bbe}')),
                '\u{bcc}' => ('\u{bc6}', Some('\u{bd7}')),
                'ஔ' => ('ஒ', Some('\u{bd7}')),
                'ள' | 'ழ' => ('ல', None),
                'ற' => ('ர', None),
                'ண' | 'ந' => ('ன', None),
                // Hindi
                '\u{901}' => ('\u{902}', None),
                '\u{958}'..='\u{95f}' => (NUKTA_BASES[c as usize - 0x958], None),
                '\u{929}' => ('न', None),
                '\u{931}' => ('र', None),
                '\u{934}' => ('ळ', None),
                '\u{940}' => ('\u{93f}', None),
                '\u{942}' => ('\u{941}', None),
                'ई' => ('इ', None),
                'ऊ' => ('उ', None),
                'ष' => ('श', None),
                // Russian
                'Ё' | 'ё' => ('е', None),
                'А'..='Я' => (char::from_u32(c as u32 + 0x20)?, None),
                _ => (c, None),
            };
            folded.push(first)?;
            if let Some(second) = second {
                folded.push(second)?;
            }
        }
        folded.merge_half_nasals();
        Some(folded)
    }

    fn push(&mut self, c: char) -> Option<()> {
        *self.chars.get_mut(self.len)? = c;
        self.len += 1;
        Some(())
    }

    fn last(&self) -> Option<char> {
        self.as_slice().last().copied()
    }

    fn as_slice(&self) -> &[char] {
        &self.chars[..self.len]
    }

    /// Turns a Hindi nasal with a virama before a consonant into the anusvara that also spells it.
    fn merge_half_nasals(&mut self) {
        let (mut read, mut kept) = (0, 0);
        while read < self.len {
            let c = self.chars[read];
            let half = matches!(c, 'ङ' | 'ञ' | 'ण' | 'न' | 'म')
                && read + 2 < self.len
                && self.chars[read + 1] == '\u{94d}'
                && ('क'..='ह').contains(&self.chars[read + 2]);
            self.chars[kept] = if half { '\u{902}' } else { c };
            kept += 1;
            read += if half { 2 } else { 1 };
        }
        self.chars[kept..self.len].fill('\0');
        self.len = kept;
    }
}

impl PartialEq for Folded {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Drop for Folded {
    fn drop(&mut self) {
        self.chars.zeroize();
    }
}

fn bit(bytes: &[u8], at: usize) -> u16 {
    (bytes[at / 8] >> (7 - at % 8) & 1) as u16
}

/// CRC-16/CCITT-FALSE. Only for catching typos.
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc << 1 ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, format, string::String, vec::Vec};

    fn factor(seed: u64) -> [u8; FACTOR_LEN] {
        let mut state = seed;
        core::array::from_fn(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        })
    }

    fn spelled(factor: &[u8; FACTOR_LEN], spelling: Spelling) -> Vec<&'static str> {
        factor_to_words(factor, spelling)
            .indices()
            .iter()
            .map(|&i| word(i))
            .collect()
    }

    fn list(n: usize) -> Vec<&'static str> {
        LISTS[n].lines().collect()
    }

    #[test]
    fn both_spellings_round_trip() {
        for seed in 0..50 {
            let factor = factor(seed);
            for spelling in [Spelling::English, Spelling::Polyglot] {
                let words = spelled(&factor, spelling);
                assert_eq!(words.len(), spelling.word_count());
                assert_eq!(words_to_factor(&words.join(" ")).unwrap(), factor);
            }
        }
    }

    #[test]
    fn polyglot_phrases_draw_on_every_list() {
        let mut seen = [false; 4];
        for seed in 0..20 {
            for &i in factor_to_words(&factor(seed), Spelling::Polyglot).indices() {
                seen[i as usize / LIST_LEN] = true;
            }
        }
        assert_eq!(seen, [true; 4]);
    }

    #[test]
    fn short_and_uppercase_words_are_accepted() {
        let factor = factor(5);
        let shortened: Vec<String> = spelled(&factor, Spelling::English)
            .iter()
            .map(|w| w.get(..4).unwrap_or(w).to_uppercase())
            .collect();
        assert_eq!(words_to_factor(&shortened.join("  ")).unwrap(), factor);
    }

    #[test]
    fn every_list_holds_2048_words_told_apart_after_folding() {
        for n in [ENGLISH, TAMIL, HINDI, RUSSIAN] {
            let words = list(n);
            assert_eq!(words.len(), LIST_LEN);
            let mut keys = HashSet::new();
            let mut prefixes = HashSet::new();
            for w in &words {
                let key: Vec<char> = if n == ENGLISH {
                    w.chars().collect()
                } else {
                    Folded::new(w).unwrap().as_slice().to_vec()
                };
                let prefix: Vec<char> = key.iter().copied().take(4).collect();
                assert!(keys.insert(key), "{w} folds onto another word");
                if n == ENGLISH || n == RUSSIAN {
                    assert!(prefixes.insert(prefix), "{w} shares its first four letters");
                }
            }
        }
    }

    #[test]
    fn every_word_is_found_where_it_is_listed() {
        for index in 0..4 * LIST_LEN as u16 {
            assert_eq!(lookup(word(index), Spelling::Polyglot), Some(index));
        }
        assert_eq!(lookup(word(TAMIL as u16 * 2048), Spelling::English), None);
    }

    /// Each Tamil and Hindi word, retyped with every confusable letter swapped for another of its
    /// kind, and each Russian word in capitals with ё and a decomposed й, is still the same word.
    #[test]
    fn confusable_spellings_find_the_same_word() {
        let retype = |c: char| -> String {
            match c {
                'ல' => "ழ".into(),
                'ள' => "ல".into(),
                'ழ' => "ள".into(),
                'ர' => "ற".into(),
                'ற' => "ர".into(),
                'ண' => "ந".into(),
                'ந' => "ன".into(),
                'ன' => "ண".into(),
                '\u{bca}' => "\u{bc6}\u{bbe}".into(),
                '\u{bcb}' => "\u{bc7}\u{bbe}".into(),
                '\u{93f}' => "\u{940}".into(),
                '\u{940}' => "\u{93f}".into(),
                '\u{941}' => "\u{942}".into(),
                '\u{942}' => "\u{941}".into(),
                'श' => "ष".into(),
                'ष' => "श".into(),
                'ं' => "ँ".into(),
                'ड' => "ड़".into(),
                'й' => "И\u{306}".into(),
                'е' => "Ё".into(),
                c => c.to_uppercase().collect(),
            }
        };
        for index in LIST_LEN as u16..4 * LIST_LEN as u16 {
            let retyped: String = word(index).chars().map(retype).collect();
            assert_eq!(
                lookup(&retyped, Spelling::Polyglot),
                Some(index),
                "{retyped} for {}",
                word(index)
            );
        }
    }

    #[test]
    fn folding_examples() {
        let same = |a: &str, b: &str| Folded::new(a).unwrap() == Folded::new(b).unwrap();
        assert!(same("பழம்", "பலம்"));
        assert!(same("ஆலோசனை", "ஆலே\u{bbe}சனை"));
        assert!(same("हिन्दी", "हिंदी"));
        assert!(same("हिंदी", "हिंदि"));
        assert!(same("कपड़ा", "कपडा"));
        assert!(same("ЁЛКА", "елка"));
        assert!(same("айсберг", "аи\u{306}сберг"));
        assert!(same("अ\u{200d}ंक", "अंक"));
        assert!(!same("अंक", "अंग"));
        assert!(!same("сон", "сын"));
    }

    #[test]
    fn russian_words_can_be_shortened_like_english() {
        for index in RUSSIAN as u16 * 2048..4 * 2048 {
            let full = word(index);
            let short: String = full.chars().take(4).collect();
            assert_eq!(lookup(&short, Spelling::Polyglot), Some(index), "{full}");
        }
        let tamil = word(TAMIL as u16 * 2048 + 100);
        let cut: String = tamil.chars().take(tamil.chars().count() - 1).collect();
        assert_eq!(
            lookup(&cut, Spelling::Polyglot),
            None,
            "Tamil is typed whole"
        );
    }

    #[test]
    fn checksum_catches_most_single_wrong_words() {
        for spelling in [Spelling::English, Spelling::Polyglot] {
            let indices: Vec<u16> = factor_to_words(&factor(6), spelling).indices().to_vec();
            let modulus = if spelling == Spelling::English {
                2048
            } else {
                8192
            };
            let mut caught = 0;
            let mut tried = 0;
            for position in 0..indices.len() {
                for replacement in [7u16, 500, 1999, 4100] {
                    let mut swapped = indices.clone();
                    swapped[position] = (indices[position] + replacement) % modulus;
                    let text: Vec<&str> = swapped.iter().map(|&i| word(i)).collect();
                    tried += 1;
                    if words_to_factor(&text.join(" ")) == Err(Error::BadWords) {
                        caught += 1;
                    }
                }
            }
            assert!(
                caught * 100 >= tried * 95,
                "{spelling:?}: caught {caught} of {tried}"
            );
        }
    }

    #[test]
    fn malformed_phrases_are_refused() {
        let factor = factor(7);
        for spelling in [Spelling::English, Spelling::Polyglot] {
            let good = spelled(&factor, spelling).join(" ");
            let missing: Vec<&str> = good.split(' ').skip(1).collect();
            assert_eq!(words_to_factor(&missing.join(" ")), Err(Error::BadWords));
            assert_eq!(
                words_to_factor(&format!("{good} abandon")),
                Err(Error::BadWords)
            );
            assert_eq!(
                words_to_factor(&good.replacen(' ', " notaword ", 1)),
                Err(Error::BadWords)
            );
            let mut unknown = spelled(&factor, spelling);
            unknown[0] = "notaword";
            assert_eq!(words_to_factor(&unknown.join(" ")), Err(Error::BadWords));
        }
        let english = spelled(&factor, Spelling::English);
        let mut mixed: Vec<&str> = english.clone();
        mixed[3] = word(RUSSIAN as u16 * 2048);
        assert_eq!(
            words_to_factor(&mixed.join(" ")),
            Err(Error::BadWords),
            "27 words are always English"
        );
    }

    #[test]
    fn crc16_check_value() {
        assert_eq!(crc16(b"123456789"), 0x29b1);
    }
}
