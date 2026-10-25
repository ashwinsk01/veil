//! One-time Carter–Wegman authenticator: POLYVAL (RFC 8452) under a hash key, masked by a pad.
//!
//! Secure against unbounded adversaries as long as each pad is used once. POLYVAL is linear in
//! the message, which is what lets a refresh correct every tag without reading any share.

use crate::format::{HASH_KEY_LEN, TAG_LEN};
use polyval::Polyval;
use polyval::universal_hash::UniversalHash;
use zeroize::Zeroize;

/// POLYVAL under `hash_key` over `msg` zero-padded to whole blocks, then `final_block`.
fn polyval(hash_key: &[u8], msg: &[u8], final_block: [u8; 16]) -> [u8; 16] {
    let mut h = polyval::Key::default();
    h.copy_from_slice(hash_key);
    let mut state = Polyval::new(&h);
    h[..].zeroize();
    state.update_padded(msg);
    state.update(&[final_block.into()]);
    let mut out = [0; 16];
    out.copy_from_slice(&state.finalize());
    out
}

/// Tag of `msg` under a 32-byte key (hash key ‖ pad): POLYVAL(msg ‖ length block) ⊕ pad.
pub(crate) fn tag(key: &[u8], msg: &[u8]) -> [u8; TAG_LEN] {
    let mut len_block = [0; 16];
    len_block[..8].copy_from_slice(&(msg.len() as u64 * 8).to_le_bytes());
    let mut hash = polyval(&key[..HASH_KEY_LEN], msg, len_block);
    let mut out = hash;
    xor_into(&mut out, &key[HASH_KEY_LEN..]);
    hash.zeroize();
    out
}

/// How a tag changes when its message is XORed with `delta` of the same length and the pad stays
/// put. The length blocks cancel, so this is POLYVAL(delta ‖ zero block).
pub(crate) fn tag_delta(hash_key: &[u8], delta: &[u8]) -> [u8; TAG_LEN] {
    polyval(hash_key, delta, [0; 16])
}

pub(crate) fn xor_into(acc: &mut [u8], other: &[u8]) {
    for (a, b) in acc.iter_mut().zip(other) {
        *a ^= b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8452 Appendix A: POLYVAL(H, X_1, X_2).
    #[test]
    fn polyval_matches_rfc_8452() {
        let h = [
            0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b,
            0x75, 0x7b,
        ];
        let x1 = [
            0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01,
            0xa2, 0x62,
        ];
        let x2 = [
            0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9,
            0xf3, 0x62,
        ];
        let expected = [
            0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5,
            0xb7, 0x7e,
        ];
        assert_eq!(polyval(&h, &x1, x2), expected);
    }

    /// The property refresh relies on: tag(m) ⊕ tag(m ⊕ d) = tag_delta(d), for whole and partial
    /// final blocks alike.
    #[test]
    fn tags_are_linear_in_the_message() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5c);
        for len in [0, 1, 15, 16, 17, 100, 10_750] {
            let mut m = [0u8; 10_750];
            let mut d = [0u8; 10_750];
            for i in 0..len {
                m[i] = (i as u8).wrapping_mul(13);
                d[i] = (i as u8).wrapping_mul(7) ^ 0xa1;
            }
            let mut moved = m;
            xor_into(&mut moved[..len], &d[..len]);
            let mut lhs = tag(&key, &m[..len]);
            xor_into(&mut lhs, &tag(&key, &moved[..len]));
            assert_eq!(lhs, tag_delta(&key[..HASH_KEY_LEN], &d[..len]), "len={len}");
        }
    }
}
