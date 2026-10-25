//! Arithmetic in GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1.
//!
//! Every operation runs in constant time: no branches or table lookups depend on operand values.

/// Multiplies two field elements by shift-and-add with masked reduction.
pub(crate) fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    product
}

/// Multiplicative inverse as a^254 (Fermat's little theorem). Maps 0 to 0.
pub(crate) fn inv(a: u8) -> u8 {
    let mut square = a;
    let mut result = 1u8;
    for _ in 0..7 {
        square = mul(square, square);
        result = mul(result, square);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook reference: carry-less product, then long division by 0x11B.
    fn mul_reference(a: u8, b: u8) -> u8 {
        let mut p: u16 = 0;
        for i in 0..8 {
            if (b >> i) & 1 == 1 {
                p ^= (a as u16) << i;
            }
        }
        for i in (8..15).rev() {
            if (p >> i) & 1 == 1 {
                p ^= 0x11b << (i - 8);
            }
        }
        p as u8
    }

    #[test]
    fn matches_reference_for_every_pair() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul_reference(a, b), "{a:#04x} * {b:#04x}");
            }
        }
    }

    #[test]
    fn fips_197_examples() {
        assert_eq!(mul(0x57, 0x83), 0xc1);
        assert_eq!(mul(0x57, 0x13), 0xfe);
    }

    /// No two non-zero elements multiply to zero, so 0x11B is irreducible and this is a field.
    #[test]
    fn no_zero_divisors() {
        for a in 1..=255u8 {
            for b in 1..=255u8 {
                assert_ne!(mul(a, b), 0, "{a:#04x} * {b:#04x}");
            }
        }
    }

    #[test]
    fn every_nonzero_element_inverts() {
        assert_eq!(inv(0), 0);
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a:#04x}");
        }
    }
}
