use {
    super::{uint_exp::UintExp, ModRing, RingRef, RingRefExt, UintMont},
    num_traits::{Inv, One, Pow, Zero},
    rand::{
        distributions::{Distribution, Standard},
        Rng,
    },
    std::{
        fmt::{self, Formatter},
        iter::{Product, Sum},
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

/// Element of a [`ModRing`].
#[derive(Clone, Copy)]
pub struct ModRingElement<Ring: RingRef> {
    ring:  Ring,
    value: Ring::Uint,
}

/// ModRingElement with the ring parameters by embedded reference.
pub type ModRingElementRef<'a, Uint> = ModRingElement<&'a ModRing<Uint>>;

impl<Ring: RingRef> ModRingElement<Ring> {
    #[inline]
    #[must_use]
    pub const fn from_montgomery(ring: Ring, value: Ring::Uint) -> Self {
        Self { ring, value }
    }

    #[inline]
    #[must_use]
    pub fn ring(&self) -> &ModRing<Ring::Uint> {
        &self.ring
    }

    #[inline]
    #[must_use]
    pub const fn as_montgomery(self) -> Ring::Uint {
        self.value
    }

    // Note: We can not implement `From<Ring::Uint>` for `ModRingElement<Ring>`
    // because this conflicts with `impl T From<T> for T` and we can't tell
    // the compiler that `Ring` and `Ring::Uint` are not the same type.
    #[inline]
    #[must_use]
    pub fn to_uint(self) -> Ring::Uint {
        self.ring.mont_mul(self.value, Ring::Uint::from_u64(1))
    }

    #[inline]
    #[must_use]
    pub fn square(mut self) -> Self {
        self.value = self.ring.mont_square(self.value);
        self
    }

    /// Small exponentiation
    ///
    /// Run time may depend on the exponent, use [`pow_ct`] if constant time or
    /// large exponents are required.
    #[inline]
    #[must_use]
    pub fn pow(self, exponent: usize) -> Self {
        match exponent {
            0 => self.ring.one(),
            1 => self,
            n if n % 2 == 0 => self.pow(n / 2).square(),
            n => self * self.pow(n / 2).square(),
        }
    }
}

impl<Ring: RingRef + Default> ModRingElement<Ring> {
    #[inline]
    #[must_use]
    pub fn from(value: Ring::Uint) -> Self {
        Ring::default().from(value)
    }
}

impl<Ring: RingRef> ModRingElement<Ring>
where
    Ring::Uint: ConditionallySelectable,
{
    /// Constant-time exponentation with arbitrary unsigned int exponent.
    #[must_use]
    pub fn pow_ct<U: UintExp>(self, exponent: U) -> Self {
        let mut result = self.ring.one();
        let mut power = self;
        // We use `bit_len` here as an optimization when B >> log_2 exponent.
        // However, this does result in leaking the number of leading zeros.
        for i in 0..exponent.bit_len() {
            let product = result * power;
            result.conditional_assign(&product, exponent.bit_ct(i));
            power *= power;
        }
        let value = result.value;
        self.ring.from_montgomery(value)
    }
}

macro_rules! forward_fmt {
    ($($trait:path),+) => {
        $(
            impl<Ring: RingRef> $trait for ModRingElement<Ring> where Ring::Uint: $trait {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    let uint = self.to_uint();
                    <Ring::Uint as $trait>::fmt(&uint, f)
                }
            }
        )+
    };
}

forward_fmt!(
    fmt::Debug,
    fmt::Display,
    fmt::Binary,
    fmt::Octal,
    fmt::LowerHex,
    fmt::UpperHex
);

impl<Ring: RingRef> PartialEq for ModRingElement<Ring> {
    fn eq(&self, other: &Self) -> bool {
        assert_eq!(*self.ring, *other.ring);
        self.value.ct_eq(&other.value).into()
    }
}

impl<Ring: RingRef> Eq for ModRingElement<Ring> {}

impl<Ring: RingRef + Default> Zero for ModRingElement<Ring> {
    fn zero() -> Self {
        Self::from_montgomery(Ring::default(), Ring::Uint::from_u64(0))
    }

    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl<Ring: RingRef + Default> One for ModRingElement<Ring> {
    fn one() -> Self {
        let ring = Ring::default();
        Self::from_montgomery(ring, ring.montgomery_r())
    }

    fn is_one(&self) -> bool {
        self.value == self.ring.montgomery_r()
    }

    fn set_one(&mut self) {
        self.value = self.ring.montgomery_r()
    }
}

impl<Ring: RingRef> Add for ModRingElement<Ring> {
    type Output = Self;

    #[inline(always)]
    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl<Ring: RingRef> Sub for ModRingElement<Ring> {
    type Output = Self;

    #[inline(always)]
    fn sub(mut self, other: Self) -> Self {
        self -= other;
        self
    }
}

impl<Ring: RingRef> Mul for ModRingElement<Ring> {
    type Output = Self;

    #[inline(always)]
    fn mul(mut self, other: Self) -> Self {
        self *= other;
        self
    }
}

impl<Ring: RingRef> Neg for ModRingElement<Ring> {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self {
        self.ring.zero() - self
    }
}

impl<Ring: RingRef> Inv for ModRingElement<Ring> {
    type Output = Option<Self>;

    fn inv(self) -> Self::Output {
        let value = self.value.inv_mod(self.ring.modulus())?;
        let value = self.ring.mont_mul(value, self.ring.montgomery_r3());
        Some(self.ring.from_montgomery(value))
    }
}

impl<Ring: RingRef> Div for ModRingElement<Ring> {
    type Output = Option<Self>;

    /// Division
    ///
    /// Run time may depend on the value of the divisor.
    #[inline(always)]
    fn div(self, other: Self) -> Option<Self> {
        assert_eq!(self.ring(), other.ring());
        other.inv().map(|inv| self * inv)
    }
}

impl<Ring: RingRef> AddAssign for ModRingElement<Ring> {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        assert_eq!(self.ring(), other.ring());
        self.value = self.value.add_mod(other.value, self.ring.modulus());
    }
}

impl<Ring: RingRef> SubAssign for ModRingElement<Ring> {
    #[inline(always)]
    fn sub_assign(&mut self, other: Self) {
        assert_eq!(self.ring(), other.ring());
        self.value = self.value.sub_mod(other.value, self.ring.modulus());
    }
}

impl<Ring: RingRef> MulAssign for ModRingElement<Ring> {
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        assert_eq!(self.ring(), other.ring());
        self.value = self.ring.mont_mul(self.value, other.value);
    }
}

impl<Ring: RingRef> DivAssign for ModRingElement<Ring> {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs).expect("Division by non-invertible");
    }
}

impl<Ring: RingRef + Default> Sum for ModRingElement<Ring> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, e| acc + e)
            .unwrap_or_else(|| Ring::default().zero())
    }
}

impl<Ring: RingRef + Default> Product for ModRingElement<Ring> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, e| acc * e)
            .unwrap_or_else(|| Ring::default().one())
    }
}

impl<Ring: RingRef + Default> Distribution<ModRingElement<Ring>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ModRingElement<Ring> {
        Ring::default().random(rng)
    }
}

impl<Ring: RingRef> ConditionallySelectable for ModRingElement<Ring>
where
    Ring::Uint: ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        assert_eq!(a.ring(), b.ring());
        let value = Ring::Uint::conditional_select(&a.value, &b.value, choice);
        a.ring.from_montgomery(value)
    }
}

impl<Ring: RingRef> ConstantTimeEq for ModRingElement<Ring>
where
    Ring::Uint: ConstantTimeEq,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        assert_eq!(self.ring(), other.ring());
        self.value.ct_eq(&other.value)
    }
}

impl<Ring: RingRef, U: UintExp> Pow<U> for ModRingElement<Ring>
where
    Ring::Uint: ConditionallySelectable,
{
    type Output = Self;

    fn pow(self, rhs: U) -> Self::Output {
        self.pow_ct(rhs)
    }
}

// Mixed ring power operations.
// Realy only useful if RingB is a subgroup of the multiplicative group of
// RingA.
impl<RingA: RingRef, RingB: RingRef> Pow<ModRingElement<RingB>> for ModRingElement<RingA>
where
    RingA::Uint: ConditionallySelectable,
    RingB::Uint: UintExp,
{
    type Output = Self;

    fn pow(self, rhs: ModRingElement<RingB>) -> Self::Output {
        self.pow_ct(rhs.to_uint())
    }
}
