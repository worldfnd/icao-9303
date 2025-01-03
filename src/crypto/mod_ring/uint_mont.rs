use {
    super::{ModRing, UintExp},
    rand::Rng,
    ruint::{aliases::U64, Uint},
    std::fmt::Debug,
    subtle::{ConditionallySelectable, ConstantTimeEq},
};

/// Trait for Uint backends supporting Montgomery multiplication.
///
/// The only implemented backed is Ruint, but the code is cleaner
/// if we abstract this, otherwise we would have to pass along the
/// const-generic parameters everywhere.
pub trait UintMont:
    Sized
    + Copy
    + PartialEq
    + Eq
    + PartialOrd
    + Debug
    + ConstantTimeEq
    + ConditionallySelectable
    + UintExp
{
    fn parameters_from_modulus(modulus: Self) -> ModRing<Self>;
    fn from_u64(value: u64) -> Self;
    fn random<R: Rng + ?Sized>(rng: &mut R, max: Self) -> Self;
    fn add_mod(self, other: Self, modulus: Self) -> Self;
    fn sub_mod(self, other: Self, modulus: Self) -> Self;
    fn mul_redc(self, other: Self, modulus: Self, mod_inv: u64) -> Self;
    fn square_redc(self, modulus: Self, mod_inv: u64) -> Self;
    fn inv_mod(self, modulus: Self) -> Option<Self>;

    /// Square root in Montgomery form.
    fn sqrt_mont(self, modulus: Self, mont_r: Self, mod_inv: u64) -> Option<Self>;

    fn from_be_bytes(bytes: &[u8]) -> Self;
    fn to_be_bytes(&self) -> Vec<u8>;
}

impl<const BITS: usize, const LIMBS: usize> UintMont for Uint<BITS, LIMBS> {
    fn parameters_from_modulus(modulus: Self) -> ModRing<Self> {
        let mod_inv = U64::wrapping_from(modulus)
            .inv_ring()
            .expect("Modulus not an odd positive integer.")
            .wrapping_neg()
            .to();

        // montgomery_r2 = 2^(128 * LIMBS) mod modulus.
        let mut montgomery_r2 = Self::ZERO;
        if Self::BITS > 32 {
            montgomery_r2.set_bit(32 * Self::LIMBS, true);
        } else {
            montgomery_r2 = Self::from((1_u64 << 32) % modulus.to::<u64>());
        }
        montgomery_r2 = montgomery_r2.mul_mod(montgomery_r2, modulus);
        montgomery_r2 = montgomery_r2.mul_mod(montgomery_r2, modulus);
        ModRing::from_parameters(modulus, montgomery_r2, mod_inv)
    }

    #[inline]
    fn from_u64(value: u64) -> Self {
        Self::from(value)
    }

    fn random<R: Rng + ?Sized>(rng: &mut R, max: Self) -> Self {
        let leading_zeros = max.leading_zeros();
        loop {
            let mut value = rng.gen::<Self>();
            value >>= leading_zeros;
            if value <= max {
                return value;
            }
        }
    }

    #[inline]
    fn add_mod(self, other: Self, modulus: Self) -> Self {
        let (sum, carry) = self.overflowing_add(other);
        let (reduced, borrow) = sum.overflowing_sub(modulus);
        if carry | !borrow {
            reduced
        } else {
            sum
        }
    }

    #[inline]
    fn sub_mod(self, other: Self, modulus: Self) -> Self {
        let (result, borrow) = self.overflowing_sub(other);
        if borrow {
            result.wrapping_add(modulus)
        } else {
            result
        }
    }

    #[inline]
    fn mul_redc(self, other: Self, modulus: Self, mod_inv: u64) -> Self {
        Self::mul_redc(self, other, modulus, mod_inv)
    }

    #[inline]
    fn square_redc(self, modulus: Self, mod_inv: u64) -> Self {
        Self::square_redc(self, modulus, mod_inv)
    }

    #[inline]
    fn inv_mod(self, modulus: Self) -> Option<Self> {
        Self::inv_mod(self, modulus)
    }

    #[inline]
    fn sqrt_mont(self, modulus: Self, mont_r: Self, mod_inv: u64) -> Option<Self> {
        // TODO: This requires modulus to be prime.
        let candidate = match modulus.to::<u64>() & 3 {
            3 | 7 => {
                let exponent = (modulus >> 2) + Self::from_u64(1);
                pow(self, exponent, modulus, mont_r, mod_inv)
            }
            5 => {
                let exponent = (modulus >> 3) + Self::from_u64(1);
                let candidate = pow(self, exponent, modulus, mont_r, mod_inv);
                if candidate.square_redc(modulus, mod_inv) == self {
                    return Some(candidate);
                }
                // Multiply by 2^((modulus - 1) / 4)
                let exponent = modulus >> 2;
                let two = mont_r.add_mod(mont_r, modulus);
                let factor = pow(two, exponent, modulus, mont_r, mod_inv);
                candidate.mul_redc(factor, modulus, mod_inv)
            }
            _ => unimplemented!("Square root only implemented for primes that are 3, 5, 7 mod 8."),
        };
        if candidate.square_redc(modulus, mod_inv) == self {
            Some(candidate)
        } else {
            None
        }
    }

    #[inline]
    fn from_be_bytes(bytes: &[u8]) -> Self {
        Self::from_be_slice(bytes)
    }

    #[inline]
    fn to_be_bytes(&self) -> Vec<u8> {
        self.to_be_bytes_vec()
    }
}

fn pow<const BITS: usize, const LIMBS: usize>(
    base: Uint<BITS, LIMBS>,
    exponent: Uint<BITS, LIMBS>,
    modulus: Uint<BITS, LIMBS>,
    mont_r: Uint<BITS, LIMBS>,
    mod_inv: u64,
) -> Uint<BITS, LIMBS> {
    let mut result = mont_r;
    let mut power = base;
    for i in 0..exponent.bit_len() {
        if exponent.bit(i) {
            result = result.mul_redc(power, modulus, mod_inv);
        }
        power = power.square_redc(modulus, mod_inv);
    }
    result
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ruint::{
            aliases::{U160, U256},
            uint, Uint,
        },
    };

    #[test]
    fn test_m31_param() {
        type U32 = Uint<32, 1>;
        let modulus = uint!(2147483647_U32);
        let ring = U32::parameters_from_modulus(modulus);
        assert_eq!(ring.modulus(), modulus);
        assert_eq!(ring.mod_inv(), 4611686020574871553_u64);
        assert_eq!(ring.montgomery_r(), uint!(4_U32));
        assert_eq!(ring.montgomery_r2(), uint!(16_U32));
        assert_eq!(ring.montgomery_r3(), uint!(64_U32));
    }

    #[test]
    fn test_goldilocks_param() {
        let modulus = uint!(18446744069414584321_U64);
        let ring = U64::parameters_from_modulus(modulus);
        assert_eq!(ring.modulus(), modulus);
        assert_eq!(ring.mod_inv(), 18446744069414584319_u64);
        assert_eq!(ring.montgomery_r(), uint!(4294967295_U64));
        assert_eq!(ring.montgomery_r2(), uint!(18446744065119617025_U64));
        assert_eq!(ring.montgomery_r3(), uint!(1_U64));
    }

    #[test]
    fn test_group1_param() {
        let modulus = uint!(1399252811935680595399801714158014275474696840019_U160);
        let ring = U160::parameters_from_modulus(modulus);
        assert_eq!(ring.modulus(), modulus);
        assert_eq!(ring.mod_inv(), 17279742035199256357_u64);
        assert_eq!(
            ring.montgomery_r(),
            uint!(276211425656182617693326127057814954281194144797_U160)
        );
        assert_eq!(
            ring.montgomery_r2(),
            uint!(1328697288359250963969439540253036463178824026347_U160)
        );
        assert_eq!(
            ring.montgomery_r3(),
            uint!(604439593675794661367692917915221321770756884129_U160)
        );
    }

    #[test]
    fn test_bn254_param() {
        let modulus = uint!(
            21888242871839275222246405745257275088548364400416034343698204186575808495617_U256
        );
        let ring = U256::parameters_from_modulus(modulus);
        assert_eq!(ring.modulus(), modulus);
        assert_eq!(
            ring.montgomery_r(),
            uint!(
                6350874878119819312338956282401532410528162663560392320966563075034087161851_U256
            )
        );
        assert_eq!(
            ring.montgomery_r2(),
            uint!(944936681149208446651664254269745548490766851729442924617792859073125903783_U256)
        );
        assert_eq!(
            ring.montgomery_r3(),
            uint!(
                5866548545943845227489894872040244720403868105578784105281690076696998248512_U256
            )
        );
        assert_eq!(ring.mod_inv(), 14042775128853446655_u64);
    }
}
