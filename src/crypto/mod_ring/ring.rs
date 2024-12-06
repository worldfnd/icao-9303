use super::UintMont;

/// Ring of integers modulo an odd positive integer.
/// TODO: Support even positive integers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ModRing<Uint: UintMont> {
    modulus: Uint,

    // Precomputed values for Montgomery multiplication.
    montgomery_r:  Uint, // R = 2^64*LIMBS mod modulus
    montgomery_r2: Uint, // R^2, or R in Montgomery form
    montgomery_r3: Uint, // R^3, or R^2 in Montgomery form
    mod_inv:       u64,  // -1 / modulus mod 2^64
}

impl<Uint: UintMont> ModRing<Uint> {
    pub fn from_parameters(modulus: Uint, montgomery_r2: Uint, mod_inv: u64) -> Self {
        let montgomery_r = Uint::mul_redc(montgomery_r2, Uint::from_u64(1), modulus, mod_inv);
        let montgomery_r3 = Uint::square_redc(montgomery_r2, modulus, mod_inv);
        Self {
            modulus,
            montgomery_r,
            montgomery_r2,
            montgomery_r3,
            mod_inv,
        }
    }

    #[inline]
    #[must_use]
    pub fn from_modulus(modulus: Uint) -> Self {
        Uint::parameters_from_modulus(modulus)
    }

    #[inline]
    #[must_use]
    pub const fn modulus(&self) -> Uint {
        self.modulus
    }

    #[inline]
    #[must_use]
    pub const fn montgomery_r(&self) -> Uint {
        self.montgomery_r
    }

    #[inline]
    #[must_use]
    pub const fn montgomery_r2(&self) -> Uint {
        self.montgomery_r2
    }

    #[inline]
    #[must_use]
    pub const fn montgomery_r3(&self) -> Uint {
        self.montgomery_r3
    }

    #[inline]
    #[must_use]
    pub const fn mod_inv(&self) -> u64 {
        self.mod_inv
    }

    /// Montogomery multiplication for the ring.
    #[inline]
    #[must_use]
    pub(super) fn mont_mul(&self, a: Uint, b: Uint) -> Uint {
        a.mul_redc(b, self.modulus, self.mod_inv)
    }

    /// Montgomery squaring for the ring.
    #[inline]
    #[must_use]
    pub(super) fn mont_square(&self, a: Uint) -> Uint {
        a.square_redc(self.modulus, self.mod_inv)
    }
}
