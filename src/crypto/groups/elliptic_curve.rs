use {
    super::{
        super::mod_ring::{ModRing, ModRingElementRef, RingRefExt, UintExp, UintMont},
        CryptoGroup,
    },
    anyhow::{ensure, Result},
    num_traits::Inv,
    std::{
        fmt::{self, Debug, Formatter},
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    base_field:      ModRing<U>,
    scalar_field:    ModRing<V>,
    a_monty:         U,
    b_monty:         U,
    cofactor:        V,
    generator_monty: (U, U),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    curve:       &'a EllipticCurve<U, V>,
    coordinates: Coordinates<'a, U>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Coordinates<'a, U>
where
    U: UintMont + ConditionallySelectable,
{
    Infinity,
    Affine(ModRingElementRef<'a, U>, ModRingElementRef<'a, U>),
}

impl<U, V> EllipticCurve<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    pub fn new(modulus: U, a: U, b: U, x: U, y: U, order: V, cofactor: V) -> Result<Self> {
        ensure!(a < modulus, "a not in field");
        ensure!(b < modulus, "b not in field");
        ensure!(x < modulus, "x not in field");
        ensure!(y < modulus, "y not in field");
        let base_field = ModRing::from_modulus(modulus);
        let scalar_field = ModRing::from_modulus(order);
        let a = base_field.from(a);
        let b = base_field.from(b);
        let x = base_field.from(x);
        let y = base_field.from(y);

        // Ensure non-singular
        let c4 = base_field.from_u64(4);
        let c27 = base_field.from_u64(27);
        ensure!(
            c4 * a.pow(3) + c27 * b.pow(2) != base_field.zero(),
            "Singular curve"
        );

        // Ensure generator is on curve
        ensure!(y.pow(2) == x.pow(3) + a * x + b, "Generator not on curve");

        let curve = Self {
            base_field,
            scalar_field,
            a_monty: a.as_montgomery(),
            b_monty: b.as_montgomery(),
            cofactor,
            generator_monty: (x.as_montgomery(), y.as_montgomery()),
        };

        // Ensure generator has order `order`
        let generator = curve.generator();
        ensure!(
            generator.mul_uint(order) == curve.infinity(),
            "Generator order mismatch"
        );

        Ok(curve)
    }

    pub const fn base_field(&self) -> &ModRing<U> {
        &self.base_field
    }

    pub const fn scalar_field(&self) -> &ModRing<V> {
        &self.scalar_field
    }

    pub fn a(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.a_monty)
    }

    pub fn b(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.b_monty)
    }

    pub const fn cofactor(&self) -> V {
        self.cofactor
    }

    pub fn generator(&self) -> EllipticCurvePoint<'_, U, V> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(
                self.base_field.from_montgomery(self.generator_monty.0),
                self.base_field.from_montgomery(self.generator_monty.1),
            ),
        }
    }

    /// Point at infinity
    pub const fn infinity(&self) -> EllipticCurvePoint<'_, U, V> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Infinity,
        }
    }

    pub fn from_affine<'a>(
        &'a self,
        x: ModRingElementRef<'a, U>,
        y: ModRingElementRef<'a, U>,
    ) -> Result<EllipticCurvePoint<'a, U, V>> {
        self.ensure_valid(x, y)?;
        Ok(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    pub fn from_montgomery(
        &self,
        coordinates: Option<(U, U)>,
    ) -> Result<EllipticCurvePoint<'_, U, V>> {
        match coordinates {
            Some((x, y)) => self.from_affine(
                self.base_field.from_montgomery(x),
                self.base_field.from_montgomery(y),
            ),
            None => Ok(self.infinity()),
        }
    }

    fn ensure_valid<'a>(
        &'a self,
        x: ModRingElementRef<'a, U>,
        y: ModRingElementRef<'a, U>,
    ) -> Result<()> {
        ensure!(x.ring() == &self.base_field);
        ensure!(y.ring() == &self.base_field);

        // Check curve equation y^2 = x^3 + ax + b
        ensure!(
            y.pow(2) == x.pow(3) + self.a() * x + self.b(),
            "Point not on curve."
        );

        if self.cofactor() != V::one() {
            let point = EllipticCurvePoint {
                curve:       self,
                coordinates: Coordinates::Affine(x, y),
            };
            ensure!(
                point.mul_uint(self.scalar_field().modulus()) == self.infinity(),
                "Point not in subgroup."
            );
        }
        Ok(())
    }
}

impl<'a, U, V> EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    pub const fn curve(&self) -> &'a EllipticCurve<U, V> {
        self.curve
    }

    pub const fn as_monty(&self) -> Option<(U, U)> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, y) => Some((x.as_montgomery(), y.as_montgomery())),
        }
    }

    pub const fn x(&self) -> Option<ModRingElementRef<'a, U>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, _) => Some(x),
        }
    }

    pub const fn y(&self) -> Option<ModRingElementRef<'a, U>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(_, y) => Some(y),
        }
    }

    fn mul_uint<W: UintExp>(mut self, scalar: W) -> Self {
        let mut result = self.curve.infinity();
        for i in 0..scalar.bit_len() {
            result.conditional_assign(&(result + self), scalar.bit_ct(i));
            self += self;
        }
        result
    }
}

macro_rules! forward_fmt {
    ($($trait:path),+) => {
        $(
            impl<'a, U, V> $trait for EllipticCurvePoint<'a, U, V>
            where
                U: UintMont + ConditionallySelectable + $trait,
                V: UintMont + UintExp,
            {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    match self.coordinates {
                        Coordinates::Infinity => write!(f, "Infinity"),
                        Coordinates::Affine(x, y) => {
                            write!(f, "(")?;
                            <ModRingElementRef<'_, U> as $trait>::fmt(&x, f)?;
                            write!(f, ", ")?;
                            <ModRingElementRef<'_, U> as $trait>::fmt(&y, f)?;
                            write!(f, ")")
                        }
                    }
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

impl<U, V> Add for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        assert_eq!(self.curve, other.curve);
        // TODO: Use constant time inversions
        match (self.coordinates, other.coordinates) {
            (Coordinates::Infinity, _) => other,
            (_, Coordinates::Infinity) => self,
            (Coordinates::Affine(x1, y1), Coordinates::Affine(x2, y2)) => {
                // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
                if x1 == x2 {
                    if y1 == y2 {
                        // Point doubling
                        let lambda = (self.curve.base_field.from_u64(3) * x1.pow(2)
                            + self.curve.a())
                            / (self.curve.base_field.from_u64(2) * y1);
                        let lambda = lambda.unwrap();
                        let x3 = lambda.pow(2) - self.curve.base_field.from_u64(2) * x1;
                        let y3 = lambda * (x1 - x3) - y1;
                        EllipticCurvePoint {
                            curve:       self.curve,
                            coordinates: Coordinates::Affine(x3, y3),
                        }
                    } else {
                        // Point at infinity
                        self.curve.infinity()
                    }
                } else {
                    let lambda = (y2 - y1) / (x2 - x1);
                    let lambda = lambda.unwrap();
                    let x3 = lambda.pow(2) - x1 - x2;
                    let y3 = lambda * (x1 - x3) - y1;
                    self.curve.from_affine(x3, y3).unwrap()
                }
            }
        }
    }
}

impl<U, V> AddAssign for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<U, V> Neg for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self.coordinates {
            Coordinates::Infinity => self,
            Coordinates::Affine(x, y) => EllipticCurvePoint {
                curve:       self.curve,
                coordinates: Coordinates::Affine(x, -y),
            },
        }
    }
}

impl<U, V> Sub for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self + other.neg()
    }
}

impl<U, V> SubAssign for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<'a, U, V> Mul<ModRingElementRef<'a, V>> for EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    type Output = Self;

    fn mul(self, scalar: ModRingElementRef<'a, V>) -> Self::Output {
        assert_eq!(scalar.ring(), self.curve.scalar_field());
        self.mul_uint(scalar.to_uint())
    }
}

impl<'a, U, V> MulAssign<ModRingElementRef<'a, V>> for EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn mul_assign(&mut self, scalar: ModRingElementRef<'a, V>) {
        *self = *self * scalar;
    }
}

impl<'a, U, V> Div<ModRingElementRef<'a, V>> for EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    type Output = Option<Self>;

    fn div(self, scalar: ModRingElementRef<'a, V>) -> Self::Output {
        scalar.inv().map(|inv| self * inv)
    }
}

impl<'a, U, V> DivAssign<ModRingElementRef<'a, V>> for EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn div_assign(&mut self, scalar: ModRingElementRef<'a, V>) {
        *self = self.div(scalar).expect("Element is not invertible");
    }
}

/// Conditionally select an Elliptic Curve Point
///
/// Note: Points must have identical representation (Infinity / Affine) for
/// constant-time.
///
/// # Panics
///
/// Panics if the points are not on the same curve
impl<'a, U, V> ConditionallySelectable for EllipticCurvePoint<'a, U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        assert_eq!(a.curve, b.curve);
        use Coordinates::*;
        let coordinates = match (&a.coordinates, &b.coordinates) {
            (Infinity, Infinity) => Infinity,
            (Affine(ax, ay), Affine(bx, by)) => Affine(
                ModRingElementRef::<'a, U>::conditional_select(ax, bx, choice),
                ModRingElementRef::<'a, U>::conditional_select(ay, by, choice),
            ),
            (a, b) => {
                if bool::from(choice) {
                    *b
                } else {
                    *a
                }
            }
        };
        Self {
            curve: a.curve,
            coordinates,
        }
    }
}

/// Constant time coordinate equality check.
///
/// Warning: Only constant time in coordinates, not in Infinity / Affine cases
/// distinction.
///
/// # Panics
///
/// Panics if the points are not on the same curve
impl<U, V> ConstantTimeEq for EllipticCurvePoint<'_, U, V>
where
    U: UintMont + ConditionallySelectable + ConstantTimeEq,
    V: UintMont + UintExp,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        use Coordinates::*;
        assert_eq!(self.curve, other.curve);
        match (&self.coordinates, &other.coordinates) {
            (Infinity, Infinity) => Choice::from(1),
            (Affine(ax, ay), Affine(bx, by)) => ax.ct_eq(bx) & ay.ct_eq(by),
            _ => Choice::from(0),
        }
    }
}

impl<'a, U, V> CryptoGroup<'a> for EllipticCurve<U, V>
where
    U: 'a + UintMont + ConditionallySelectable,
    V: 'a + UintMont + UintExp,
{
    type BaseElement = EllipticCurvePoint<'a, U, V>;
    type ScalarElement = ModRingElementRef<'a, V>;

    fn generator(&'a self) -> Self::BaseElement {
        self.generator()
    }

    fn random_scalar(&'a self, rng: &mut dyn super::CryptoCoreRng) -> Self::ScalarElement {
        self.scalar_field().random(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        named::{secp192r1, secp224r1, secp256r1, secp384r1, secp521r1},
        test_dh, test_schnorr,
    };

    #[test]
    fn test_secp192r1() {
        let group = secp192r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp224r1() {
        let group = secp224r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp256r1() {
        let group = secp256r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp384r1() {
        let group = secp384r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_secp521r1() {
        let group = secp521r1();
        test_dh(&group);
        test_schnorr(&group);
    }
}
