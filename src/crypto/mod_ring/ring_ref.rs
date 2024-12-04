use {
    super::{ModRing, ModRingElement, UintMont},
    num_traits::Zero,
    rand::Rng,
    std::ops::Deref,
};

/// Trait for ModRing parameter references.
///
/// Making this a trait allows both zero-sized and references to be used, so the
/// same implementation can cover both compile-time and runtime known fields. In
/// the latter case, a sufficiently large `Uint` will have to be picked compile
/// time though.
pub trait RingRef: Copy + Deref<Target = ModRing<Self::Uint>> {
    type Uint: UintMont;
}

#[allow(clippy::wrong_self_convention)] // TODO: Do we want this?
pub trait RingRefExt: RingRef {
    fn from_montgomery(self, value: Self::Uint) -> ModRingElement<Self>;
    fn zero(self) -> ModRingElement<Self>;
    fn one(self) -> ModRingElement<Self>;
    fn from_u64(self, value: u64) -> ModRingElement<Self>;
    fn from<T: Into<Self::Uint>>(self, value: T) -> ModRingElement<Self>;
    fn random<R: Rng + ?Sized>(self, rng: &mut R) -> ModRingElement<Self>;
}

impl<Uint: UintMont> RingRef for &ModRing<Uint> {
    type Uint = Uint;
}

impl<Ring: RingRef> RingRefExt for Ring {
    #[inline(always)]
    fn from_montgomery(self, value: Ring::Uint) -> ModRingElement<Self> {
        debug_assert!(value < self.modulus());
        ModRingElement::from_montgomery(self, value)
    }

    #[inline(always)]
    fn from_u64(self, value: u64) -> ModRingElement<Self> {
        self.from(Ring::Uint::from_u64(value))
    }

    fn from<T: Into<Self::Uint>>(self, value: T) -> ModRingElement<Self> {
        let value = value.into();
        assert!(value < self.modulus());
        let value = self.mont_mul(value, self.montgomery_r2());
        self.from_montgomery(value)
    }

    #[inline(always)]
    fn zero(self) -> ModRingElement<Self> {
        self.from_montgomery(Ring::Uint::zero())
    }

    #[inline(always)]
    fn one(self) -> ModRingElement<Self> {
        self.from_montgomery(self.montgomery_r())
    }

    fn random<R: Rng + ?Sized>(self, rng: &mut R) -> ModRingElement<Self> {
        self.from_montgomery(Ring::Uint::random(rng, self.modulus()))
    }
}
