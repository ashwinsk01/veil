//! Tampering can stop Veil but never change what it rebuilds. The fuzzer edits a genuine set's
//! shares, keycards or masks; whenever Veil still accepts the result, the file must be the original.
#![no_main]

use libfuzzer_sys::fuzz_target;
use veil_core::{HashKeys, KeycardView, mask_len};
use veil_fuzz::{Counter, N, combine_or_refuse, edit, fixture};

fuzz_target!(|data: &[u8]| {
    let [what, pick, ops @ ..] = data else {
        return;
    };
    let fixture = fixture();
    let target = (what >> 2) as usize % N as usize;
    match what % 3 {
        0 => {
            let mut shares = fixture.shares.clone();
            edit(&mut shares[target], ops);
            combine_or_refuse(&shares, *pick);
        }
        1 => {
            let mut masks = fixture.masks.clone();
            edit(&mut masks[target], ops);
            combine_or_refuse(&refreshed(&masks), *pick);
        }
        _ => {
            let mut keycards = fixture.keycards.clone();
            edit(&mut keycards[target], ops);
            let Ok(cards) = keycards
                .iter()
                .map(|c| KeycardView::parse(c))
                .collect::<Result<Vec<_>, _>>()
            else {
                return;
            };
            let Ok(keys) = HashKeys::from_keycards(&cards) else {
                return;
            };
            let mut masks = vec![vec![0u8; mask_len(N)]; N as usize];
            let mut refs: Vec<&mut [u8]> = masks.iter_mut().map(|m| &mut m[..]).collect();
            if veil_core::deal(&keys, &mut Counter(2), &mut refs).is_ok() {
                combine_or_refuse(&refreshed(&masks), *pick);
            }
        }
    }
});

/// Each share after applying its mask, or as it was if the mask is refused.
fn refreshed(masks: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut shares = fixture().shares.clone();
    for (share, mask) in shares.iter_mut().zip(masks) {
        let mut next = share.clone();
        if veil_core::apply(&mut next, mask).is_ok() {
            *share = next;
        }
    }
    shares
}
