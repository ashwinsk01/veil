//! Arbitrary bytes into everything Veil reads from outside: share, keycard and mask files, device
//! helper data, composed payloads and typed words. Each must refuse bad input, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_core::{FACTOR_LEN, HashKeys, KeycardView, ShareView, fuzzy, keycard_len};
use veil_fuzz::fixture;

fuzz_target!(|data: &[u8]| {
    if let Ok(share) = ShareView::parse(data) {
        let mut card = vec![0u8; keycard_len(share.total())];
        let _ = veil_core::keycard(&share, &mut card);
        let _ = veil_core::verify(&[share]);
    }
    if let Ok(card) = KeycardView::parse(data) {
        let _ = HashKeys::from_keycards(&[card]);
    }
    let mut share = fixture().shares[0].clone();
    let _ = veil_core::apply(&mut share, data);

    let mut factor = [0u8; FACTOR_LEN];
    let (response, helper) = data.split_at(data.len() / 2);
    let _ = fuzzy::reproduce(response, helper, &mut factor);
    let _ = fuzzy::reproduce(helper, response, &mut factor);
    let mut key = [0u8; 32];
    let _ = veil_core::recover(data, &factor, None, &mut key);
    let _ = veil_core::recover(data, &factor, Some(&factor), &mut key);
    let _ = veil_core::words_to_factor(&String::from_utf8_lossy(data));
});
