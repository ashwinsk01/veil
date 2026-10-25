//! Every way of typing the same phrase decodes to the same factor: any case, English and Russian
//! words cut to four letters, confusable letters swapped, joiners added, Tamil vowel signs and
//! Russian й and ё decomposed, Hindi anusvara written as a half nasal, any whitespace between words.
#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_core::{FACTOR_LEN, Spelling};

const SEPARATORS: [&str; 5] = [" ", "  ", "\n", "\t", " \r\n "];

fuzz_target!(|data: &[u8]| {
    let Some((factor, rest)) = data.split_first_chunk::<FACTOR_LEN>() else {
        return;
    };
    let Some((&how, choices)) = rest.split_first() else {
        return;
    };
    let spelling = if how & 1 == 0 {
        Spelling::English
    } else {
        Spelling::Polyglot
    };
    let phrase = veil_core::factor_to_words(factor, spelling);
    let mut text = String::new();
    for (i, &index) in phrase.indices().iter().enumerate() {
        let choice = choices.get(i).copied().unwrap_or(0);
        text.push_str(SEPARATORS[(choice >> 5) as usize % SEPARATORS.len()]);
        text.push_str(&retype(veil_core::word(index), choice));
    }
    assert_eq!(
        veil_core::words_to_factor(&text),
        Ok(*factor),
        "{text:?} no longer decodes"
    );
});

/// `word` typed differently but meaning the same, as the bits of `how` choose.
fn retype(word: &str, how: u8) -> String {
    let latin = word.is_ascii();
    let russian = word.starts_with(|c| ('\u{400}'..='\u{4ff}').contains(&c));
    let mut chars: Vec<char> = word.chars().collect();
    if how & 1 != 0 && (latin || russian) && chars.len() > 4 {
        chars.truncate(4);
    }
    if how & 2 != 0 {
        chars = chars.iter().flat_map(|c| c.to_uppercase()).collect();
    }
    if latin {
        return chars.into_iter().collect();
    }
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let before_consonant = chars.get(i + 1).is_some_and(|n| ('क'..='ह').contains(n));
        let swapped = if how & 4 != 0 {
            confusable(c, before_consonant)
        } else {
            None
        };
        let swapped = swapped.unwrap_or_else(|| c.to_string());
        let decomposed: String = swapped
            .chars()
            .map(|c| if how & 16 != 0 { decompose(c) } else { c.to_string() })
            .collect();
        out.push_str(&decomposed);
        if how & 8 != 0 && i == 0 {
            out.push('\u{200c}');
        }
    }
    if how & 8 != 0 {
        out.push('\u{200d}');
    }
    out
}

/// Another way of writing `c` that Veil must read as the same letter.
fn confusable(c: char, before_consonant: bool) -> Option<String> {
    let swapped = match c {
        'ல' => "ழ",
        'ள' => "ல",
        'ழ' => "ள",
        'ர' => "ற",
        'ற' => "ர",
        'ண' => "ந",
        'ந' => "ன",
        'ன' => "ண",
        '\u{93f}' => "\u{940}",
        '\u{940}' => "\u{93f}",
        '\u{941}' => "\u{942}",
        '\u{942}' => "\u{941}",
        'इ' => "ई",
        'ई' => "इ",
        'उ' => "ऊ",
        'ऊ' => "उ",
        'श' => "ष",
        'ष' => "श",
        'ड' => "ड\u{93c}",
        '\u{902}' if before_consonant => "न\u{94d}",
        '\u{902}' => "\u{901}",
        'е' => "ё",
        'Е' => "Ё",
        _ => return None,
    };
    Some(swapped.to_string())
}

/// `c` as a base letter and a combining mark, where it has such a form.
fn decompose(c: char) -> String {
    match c {
        '\u{bca}' => "\u{bc6}\u{bbe}".into(),
        '\u{bcb}' => "\u{bc7}\u{bbe}".into(),
        '\u{bcc}' => "\u{bc6}\u{bd7}".into(),
        'й' => "и\u{306}".into(),
        'Й' => "И\u{306}".into(),
        'ё' => "е\u{308}".into(),
        'Ё' => "Е\u{308}".into(),
        c => c.to_string(),
    }
}
