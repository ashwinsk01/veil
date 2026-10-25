//! Splitting, cross-verification and recovery.

use crate::format::{
    Header, KEY_LEN, KEYS_OFFSET, MAGIC, SetId, ShareView, TAG_LEN, Y_OFFSET, body_len,
    check_params, share_len, slot,
};
use crate::{Entropy, Error, MAX_FILE, MAX_SHARES, SECRET_LEN, Secret, gf256, mac};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Which share rejected which during cross-verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthFailures {
    /// `rows[v - 1]` has bit `s - 1` set when share `v` rejected share `s`.
    rows: [u16; MAX_SHARES],
}

impl AuthFailures {
    fn record(&mut self, verifier: u8, share: u8) {
        self.rows[verifier as usize - 1] |= 1 << (share - 1);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.iter().all(|&row| row == 0)
    }

    pub fn rejected(&self, verifier: u8, share: u8) -> bool {
        self.rows[verifier as usize - 1] >> (share - 1) & 1 == 1
    }

    /// How many shares rejected `share`.
    pub fn rejections(&self, share: u8) -> u32 {
        self.rows
            .iter()
            .map(|&row| (row >> (share - 1) & 1) as u32)
            .sum()
    }
}

/// Splits `secret` into `n` shares, any `k` of which rebuild it.
///
/// `out` must hold `n` buffers of [`share_len`]`(n)` bytes each. On error their contents are
/// unspecified and must be discarded.
pub fn split<E: Entropy + ?Sized>(
    secret: &Secret,
    k: u8,
    n: u8,
    rng: &mut E,
    out: &mut [&mut [u8]],
) -> Result<SetId, Error> {
    check_out(k, n, out)?;
    for (b, &secret_byte) in secret.bytes().iter().enumerate() {
        split_byte(out, b, secret_byte, k, rng)?;
    }
    seal(out, k, n, rng)
}

/// Splits a secret one byte at a time as it is typed, so that the whole never exists in one
/// place. Each byte gets its own fresh curve the moment it arrives. The length and the padding are
/// split at the end, and then the set is sealed. The shares are an ordinary set: [`combine`]
/// rebuilds them.
pub struct Writer<'a, 'b> {
    k: u8,
    n: u8,
    out: &'a mut [&'b mut [u8]],
    len: usize,
}

impl<'a, 'b> Writer<'a, 'b> {
    /// `out` must hold `n` buffers of [`share_len`]`(n)` bytes each.
    pub fn new(k: u8, n: u8, out: &'a mut [&'b mut [u8]]) -> Result<Self, Error> {
        check_out(k, n, out)?;
        Ok(Self { k, n, out, len: 0 })
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Splits the next byte at once. The caller should wipe its copy.
    pub fn push<E: Entropy + ?Sized>(&mut self, byte: u8, rng: &mut E) -> Result<(), Error> {
        if self.len == MAX_FILE {
            return Err(Error::FileTooLarge);
        }
        split_byte(self.out, 2 + self.len, byte, self.k, rng)?;
        self.len += 1;
        Ok(())
    }

    /// Takes back the last byte. Its position is split again by the next push or by the padding.
    pub fn pop(&mut self) {
        self.len = self.len.saturating_sub(1);
    }

    /// Splits the length and the padding, then seals the set.
    pub fn finish<E: Entropy + ?Sized>(self, rng: &mut E) -> Result<SetId, Error> {
        let length = (self.len as u16).to_be_bytes();
        split_byte(self.out, 0, length[0], self.k, rng)?;
        split_byte(self.out, 1, length[1], self.k, rng)?;
        for b in 2 + self.len..SECRET_LEN {
            split_byte(self.out, b, 0, self.k, rng)?;
        }
        seal(self.out, self.k, self.n, rng)
    }
}

fn check_out(k: u8, n: u8, out: &[&mut [u8]]) -> Result<(), Error> {
    check_params(k, n)?;
    if out.len() != n as usize || out.iter().any(|share| share.len() != share_len(n)) {
        return Err(Error::BadLength);
    }
    Ok(())
}

/// Puts one byte of the secret block on a fresh random polynomial of degree k - 1, with the byte as
/// its constant term, and gives each share its point.
fn split_byte<E: Entropy + ?Sized>(
    out: &mut [&mut [u8]],
    position: usize,
    byte: u8,
    k: u8,
    rng: &mut E,
) -> Result<(), Error> {
    let mut coeffs = Zeroizing::new([0u8; MAX_SHARES - 1]);
    let coeffs = &mut coeffs[..k as usize - 1];
    rng.fill(coeffs)?;
    for (i, share) in out.iter_mut().enumerate() {
        share[Y_OFFSET + position] = eval(byte, coeffs, i as u8 + 1);
    }
    Ok(())
}

/// Writes every header, then every pairwise key, then every tag. Keys go in before any tag,
/// because each tag covers its share's keys.
fn seal<E: Entropy + ?Sized>(
    out: &mut [&mut [u8]],
    k: u8,
    n: u8,
    rng: &mut E,
) -> Result<SetId, Error> {
    let mut set_id = [0; 16];
    rng.fill(&mut set_id)?;
    for (i, share) in out.iter_mut().enumerate() {
        let x = i as u8 + 1;
        Header {
            k,
            n,
            x,
            epoch: 0,
            set_id,
        }
        .write(share, MAGIC);
    }
    for (i, share) in out.iter_mut().enumerate() {
        for j in (0..n as usize).filter(|&j| j != i) {
            let at = KEYS_OFFSET + slot(i as u8 + 1, j as u8 + 1) * KEY_LEN;
            rng.fill(&mut share[at..at + KEY_LEN])?;
        }
    }
    let body = body_len(n);
    for j in 0..n as usize {
        for i in (0..n as usize).filter(|&i| i != j) {
            let (xi, xj) = (i as u8 + 1, j as u8 + 1);
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            let at = KEYS_OFFSET + slot(xi, xj) * KEY_LEN;
            key.copy_from_slice(&out[i][at..at + KEY_LEN]);
            let t = mac::tag(&key[..], &out[j][..body]);
            let at = body + slot(xj, xi) * TAG_LEN;
            out[j][at..at + TAG_LEN].copy_from_slice(&t);
        }
    }
    Ok(set_id)
}

/// Checks every share against every other without rebuilding anything.
///
/// Safe to run on fewer than `k` shares: it reveals nothing about the secret.
pub fn verify(shares: &[ShareView<'_>]) -> Result<(), Error> {
    check_consistent(shares.iter().map(ShareView::header))?;
    if shares.len() < 2 {
        return Err(Error::NotEnoughShares {
            have: shares.len() as u8,
            need: 2,
        });
    }
    cross_check(shares)
}

/// Cross-verifies `shares`, then rebuilds the secret into `out`. Nothing is written on failure.
pub fn combine(shares: &[ShareView<'_>], out: &mut Secret) -> Result<(), Error> {
    check_consistent(shares.iter().map(ShareView::header))?;
    let Some(first) = shares.first() else {
        return Err(Error::NotEnoughShares { have: 0, need: 2 });
    };
    let k = first.threshold();
    if shares.len() < k as usize {
        return Err(Error::NotEnoughShares {
            have: shares.len() as u8,
            need: k,
        });
    }
    cross_check(shares)?;
    reconstruct(&shares[..k as usize], out);
    if out.file().is_err() {
        out.zeroize();
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// Evaluates s + a1·x + … + a(k-1)·x^(k-1) by Horner's rule.
pub(crate) fn eval(secret_byte: u8, coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0;
    for &a in coeffs.iter().rev() {
        acc = gf256::mul(acc, x) ^ a;
    }
    gf256::mul(acc, x) ^ secret_byte
}

/// Checks that `headers` all come from one split and epoch, with no index repeated.
pub(crate) fn check_consistent(
    headers: impl ExactSizeIterator<Item = Header>,
) -> Result<(), Error> {
    if headers.len() > MAX_SHARES {
        return Err(Error::TooManyShares);
    }
    let mut first = None;
    let mut seen = 0u32;
    for header in headers {
        let first = *first.get_or_insert(header);
        let same_set = (header.k, header.n, header.epoch, header.set_id)
            == (first.k, first.n, first.epoch, first.set_id);
        if !same_set {
            return Err(Error::MixedSets);
        }
        let bit = 1 << header.x;
        if seen & bit != 0 {
            return Err(Error::DuplicateShare(header.x));
        }
        seen |= bit;
    }
    Ok(())
}

pub(crate) fn cross_check(shares: &[ShareView<'_>]) -> Result<(), Error> {
    let mut failures = AuthFailures::default();
    for verifier in shares {
        for share in shares.iter().filter(|s| s.index() != verifier.index()) {
            let expected = mac::tag(verifier.key_for(share.index()), share.body());
            if !bool::from(expected[..].ct_eq(share.tag_from(verifier.index()))) {
                failures.record(verifier.index(), share.index());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::TamperDetected(failures))
    }
}

/// Lagrange interpolation at zero over exactly `k` shares. Performs no verification.
pub(crate) fn reconstruct(used: &[ShareView<'_>], out: &mut Secret) {
    let mut lambda = [0u8; MAX_SHARES];
    for (j, share) in used.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for other in used.iter().filter(|o| o.index() != share.index()) {
            num = gf256::mul(num, other.index());
            den = gf256::mul(den, other.index() ^ share.index());
        }
        lambda[j] = gf256::mul(num, gf256::inv(den));
    }
    let buf = out.bytes_mut();
    for (b, byte) in buf.iter_mut().enumerate().take(SECRET_LEN) {
        let mut acc = 0;
        for (j, share) in used.iter().enumerate() {
            acc ^= gf256::mul(lambda[j], share.y()[b]);
        }
        *byte = acc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HEADER_LEN, MAX_FILE};
    use std::{vec, vec::Vec};

    /// Deterministic SplitMix64 stream. For tests only.
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

    fn random_file(len: usize, seed: u64) -> Vec<u8> {
        let mut file = vec![0; len];
        TestRng(seed).fill(&mut file).unwrap();
        file
    }

    fn make(k: u8, n: u8, file: &[u8], seed: u64) -> Vec<Vec<u8>> {
        let mut secret = Secret::new();
        secret.load(file).unwrap();
        let mut shares = vec![vec![0; share_len(n)]; n as usize];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        split(&secret, k, n, &mut TestRng(seed), &mut refs).unwrap();
        shares
    }

    fn views<'a>(shares: &[&'a [u8]]) -> Vec<ShareView<'a>> {
        shares
            .iter()
            .map(|s| ShareView::parse(s).unwrap())
            .collect()
    }

    fn recover(shares: &[&[u8]]) -> Result<Vec<u8>, Error> {
        let views = shares
            .iter()
            .map(|s| ShareView::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Secret::new();
        combine(&views, &mut out)?;
        Ok(out.file()?.to_vec())
    }

    #[test]
    fn every_threshold_subset_recovers_the_file() {
        for (k, n) in [(2, 2), (2, 3), (3, 5), (4, 7), (5, 5)] {
            for len in [0, 1, 777, MAX_FILE] {
                let file = random_file(len, len as u64 + n as u64);
                let shares = make(k, n, &file, 7);
                for mask in 0u32..1 << n {
                    let count = mask.count_ones() as u8;
                    if count != k && count != n {
                        continue;
                    }
                    let picked: Vec<&[u8]> = (0..n as usize)
                        .filter(|i| mask >> i & 1 == 1)
                        .map(|i| shares[i].as_slice())
                        .collect();
                    assert_eq!(
                        recover(&picked).unwrap(),
                        file,
                        "k={k} n={n} len={len} mask={mask:b}"
                    );
                }
            }
        }
    }

    #[test]
    fn fewer_than_threshold_is_refused() {
        let shares = make(3, 5, b"top secret", 1);
        let result = recover(&[&shares[0], &shares[4]]);
        assert_eq!(result, Err(Error::NotEnoughShares { have: 2, need: 3 }));
    }

    /// With k = 2 a share is s + a·x for a uniform a. That is one-to-one in a, so the share is
    /// uniform whatever s is.
    #[test]
    fn one_share_of_a_two_threshold_reveals_nothing() {
        for x in 1..=MAX_SHARES as u8 {
            for s in [0x00, 0x5a, 0xff] {
                let mut seen = [false; 256];
                for a in 0..=255u8 {
                    let y = eval(s, &[a], x) as usize;
                    assert!(!seen[y], "x={x} s={s:#04x}");
                    seen[y] = true;
                }
            }
        }
    }

    /// With k = 3, every pair of shares is a one-to-one image of the two random coefficients, so
    /// the pair is uniform over all 65,536 values whatever the secret byte is. Exhaustive, for
    /// every pair of indices a split can produce.
    #[test]
    fn two_shares_of_a_three_threshold_reveal_nothing() {
        let mut seen = vec![false; 1 << 16];
        for xa in 1..=MAX_SHARES as u8 {
            for xb in xa + 1..=MAX_SHARES as u8 {
                for s in [0x00, 0xa5] {
                    seen.fill(false);
                    for a1 in 0..=255u8 {
                        for a2 in 0..=255u8 {
                            let pair = (eval(s, &[a1, a2], xa) as usize) << 8
                                | eval(s, &[a1, a2], xb) as usize;
                            assert!(!seen[pair], "xa={xa} xb={xb} s={s:#04x}");
                            seen[pair] = true;
                        }
                    }
                }
            }
        }
    }

    /// Flip one bit at every header, key and tag byte, and at a stride through the share data, in
    /// each share used for recovery. A changed body must always be rejected. A changed tag must be
    /// rejected exactly when its verifier is present.
    #[test]
    fn every_modified_byte_is_caught() {
        let (k, n) = (3u8, 5u8);
        let file = random_file(500, 1);
        let shares = make(k, n, &file, 2);
        let body = body_len(n);
        let positions = (0..share_len(n))
            .filter(|&p| !(HEADER_LEN..KEYS_OFFSET).contains(&p) || (p - Y_OFFSET) % 97 == 0);
        for victim in 0..k as usize {
            let x = victim as u8 + 1;
            for p in positions.clone() {
                let mut forged = shares[victim].clone();
                forged[p] ^= 0x01;
                let mut set: Vec<&[u8]> = shares[..k as usize].iter().map(Vec::as_slice).collect();
                set[victim] = &forged;
                let result = recover(&set);
                let must_fail = if p < body {
                    true
                } else {
                    let s = (p - body) / TAG_LEN;
                    let verifier = if s + 1 < x as usize { s + 1 } else { s + 2 };
                    verifier <= k as usize
                };
                if must_fail {
                    assert!(
                        result.is_err(),
                        "flip at byte {p} of share {x} went unnoticed"
                    );
                } else {
                    assert_eq!(
                        result.unwrap(),
                        file,
                        "flip at byte {p} of share {x} changed the output"
                    );
                }
            }
        }
    }

    /// Tompa–Woll: Shamir alone lets one share holder shift the recovered secret by any amount
    /// they choose. The pairwise tags stop it.
    #[test]
    fn malleability_attack_is_caught() {
        let file = b"wire 100 dollars".to_vec();
        let shares = make(3, 5, &file, 3);
        let mut forged = shares[2].clone();
        // λ for share 3 within {1, 2, 3} is 1·2 / ((1+3)(2+3)) in GF(2^8).
        let lambda = gf256::mul(gf256::mul(1, 2), gf256::inv(gf256::mul(1 ^ 3, 2 ^ 3)));
        // Turn the '1' (file byte 5, after the 2-byte length) into a '9'.
        forged[Y_OFFSET + 2 + 5] ^= gf256::mul(gf256::inv(lambda), b'1' ^ b'9');
        let set = [
            shares[0].as_slice(),
            shares[1].as_slice(),
            forged.as_slice(),
        ];

        let mut unchecked = Secret::new();
        reconstruct(&views(&set), &mut unchecked);
        assert_eq!(
            unchecked.file().unwrap(),
            b"wire 900 dollars",
            "without tags the forgery works"
        );

        match recover(&set) {
            Err(Error::TamperDetected(f)) => {
                assert_eq!(f.rejections(3), 2);
                assert_eq!(f.rejections(1) + f.rejections(2), 0);
            }
            other => panic!("forgery not caught: {other:?}"),
        }
    }

    #[test]
    fn relabelled_share_is_caught() {
        let shares = make(3, 5, b"label swap", 4);
        let mut forged = shares[2].clone();
        forged[7] = 4;
        match recover(&[&shares[0], &shares[1], &forged]) {
            Err(Error::TamperDetected(f)) => assert_eq!(f.rejections(4), 2),
            other => panic!("relabel not caught: {other:?}"),
        }
    }

    #[test]
    fn shares_from_different_splits_do_not_mix() {
        let a = make(3, 5, b"same file", 5);
        let b = make(3, 5, b"same file", 6);
        assert_eq!(recover(&[&a[0], &a[1], &b[2]]), Err(Error::MixedSets));
    }

    #[test]
    fn duplicate_share_is_refused() {
        let shares = make(3, 5, b"dup", 7);
        assert_eq!(
            recover(&[&shares[0], &shares[1], &shares[1]]),
            Err(Error::DuplicateShare(2))
        );
    }

    #[test]
    fn verify_works_below_threshold_and_spots_the_culprit() {
        let shares = make(3, 5, b"audit", 8);
        assert_eq!(verify(&views(&[&shares[0], &shares[3]])), Ok(()));

        let mut forged = shares[3].clone();
        forged[Y_OFFSET + 42] ^= 0x80;
        match verify(&views(&[&shares[0], &forged])) {
            Err(Error::TamperDetected(f)) => {
                assert!(f.rejected(1, 4));
                assert!(!f.rejected(4, 1));
            }
            other => panic!("not caught: {other:?}"),
        }
    }

    #[test]
    fn oversized_file_is_refused() {
        let mut secret = Secret::new();
        assert_eq!(
            secret.load(&vec![0; MAX_FILE + 1]),
            Err(Error::FileTooLarge)
        );
        assert_eq!(secret.load(&vec![7; MAX_FILE]), Ok(()));
        assert_eq!(secret.file().unwrap().len(), MAX_FILE);
    }

    #[test]
    fn bad_parameters_are_refused() {
        let secret = Secret::new();
        for (k, n) in [(0, 5), (1, 5), (6, 5), (2, 17)] {
            let mut shares = vec![vec![0; share_len(n)]; n as usize];
            let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
            assert_eq!(
                split(&secret, k, n, &mut TestRng(0), &mut refs),
                Err(Error::BadParams),
                "k={k} n={n}"
            );
        }
    }

    fn written(k: u8, n: u8, actions: &[Option<u8>], seed: u64) -> Vec<Vec<u8>> {
        let mut shares = vec![vec![0; share_len(n)]; n as usize];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        let mut rng = TestRng(seed);
        let mut writer = Writer::new(k, n, &mut refs).unwrap();
        for action in actions {
            match action {
                Some(byte) => writer.push(*byte, &mut rng).unwrap(),
                None => writer.pop(),
            }
        }
        writer.finish(&mut rng).unwrap();
        shares
    }

    fn typed(text: &[u8]) -> Vec<Option<u8>> {
        text.iter().map(|&b| Some(b)).collect()
    }

    #[test]
    fn written_shares_rebuild_the_text() {
        let text = b"recovery code: 7X4P-QM2D-9WKL";
        for (k, n) in [(2, 3), (3, 5), (5, 5)] {
            let shares = written(k, n, &typed(text), 50);
            assert_eq!(verify(&views(&[&shares[0], &shares[1]])), Ok(()));
            let picked: Vec<&[u8]> = shares
                .iter()
                .rev()
                .take(k as usize)
                .map(Vec::as_slice)
                .collect();
            assert_eq!(recover(&picked).unwrap(), text, "k={k} n={n}");
        }
    }

    #[test]
    fn taking_back_a_byte_rewrites_it() {
        let mut actions = typed(b"helx");
        actions.push(None);
        actions.extend(typed(b"lo"));
        let shares = written(3, 5, &actions, 51);
        let picked: Vec<&[u8]> = shares[..3].iter().map(Vec::as_slice).collect();
        assert_eq!(recover(&picked).unwrap(), b"hello");
    }

    #[test]
    fn writer_stops_at_the_largest_file() {
        let mut shares = vec![vec![0; share_len(3)]; 3];
        let mut refs: Vec<&mut [u8]> = shares.iter_mut().map(Vec::as_mut_slice).collect();
        let mut rng = TestRng(52);
        let mut writer = Writer::new(2, 3, &mut refs).unwrap();
        for _ in 0..MAX_FILE {
            writer.push(b'x', &mut rng).unwrap();
        }
        assert_eq!(writer.push(b'x', &mut rng), Err(Error::FileTooLarge));
        assert_eq!(writer.len(), MAX_FILE);
    }

    #[test]
    fn same_randomness_gives_same_shares() {
        assert_eq!(make(3, 5, b"repeatable", 9), make(3, 5, b"repeatable", 9));
        assert_ne!(make(3, 5, b"repeatable", 9), make(3, 5, b"repeatable", 10));
    }
}
