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
pub struct EllipticCurve<U: UintMont> {
    base_field:      ModRing<U>,
    scalar_field:    ModRing<U>,
    a_monty:         U,
    b_monty:         U,
    cofactor:        U,
    generator_monty: (U, U),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EllipticCurvePoint<'a, U: UintMont> {
    curve:       &'a EllipticCurve<U>,
    coordinates: Coordinates<'a, U>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Coordinates<'a, U: UintMont> {
    Infinity,
    Affine(ModRingElementRef<'a, U>, ModRingElementRef<'a, U>),
}

impl<U: UintMont> EllipticCurve<U> {
    pub fn new(modulus: U, a: U, b: U, x: U, y: U, order: U, cofactor: U) -> Result<Self> {
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
        // TODO: Check if modulus and order are prime.
        // TODO: Check Hasse bound.

        // Ensure non-singular
        let c4 = base_field.from_u64(4);
        let c27 = base_field.from_u64(27);
        ensure!(
            c4 * a.pow(3) + c27 * b.pow(2) != base_field.zero(),
            "Singular curve"
        );

        // Ensure not anomalous
        ensure!(modulus != order, "Anomalous curve");

        // Ensure high embedding degree.
        // BSI TR-03111:2018 requires embedding degree at least 10^4.
        // let p = scalar_field.from(modulus);
        // let mut pe = scalar_field.one();
        // for i in 1..=10_000 {
        //     pe *= p;
        //     ensure!(pe != scalar_field.one(), "Low embedding degree {}", i);
        // }

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

    pub const fn scalar_field(&self) -> &ModRing<U> {
        &self.scalar_field
    }

    pub fn a(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.a_monty)
    }

    pub fn b(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.b_monty)
    }

    pub const fn cofactor(&self) -> U {
        self.cofactor
    }

    pub fn generator(&self) -> EllipticCurvePoint<'_, U> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(
                self.base_field.from_montgomery(self.generator_monty.0),
                self.base_field.from_montgomery(self.generator_monty.1),
            ),
        }
    }

    /// Point at infinity
    pub const fn infinity(&self) -> EllipticCurvePoint<'_, U> {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Infinity,
        }
    }

    pub fn from_affine<'a>(
        &'a self,
        x: ModRingElementRef<'a, U>,
        y: ModRingElementRef<'a, U>,
    ) -> Result<EllipticCurvePoint<'a, U>> {
        self.ensure_valid(x, y)?;
        Ok(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    /// Returns a point with x-coordinate `x` if it exists.
    /// If a solution `p` exists, the other solution is `-p`.
    pub fn from_x<'a>(&'a self, x: ModRingElementRef<'a, U>) -> Option<EllipticCurvePoint<'a, U>> {
        assert_eq!(x.ring(), &self.base_field);
        let y2 = x.pow(3) + self.a() * x + self.b();
        let y = y2.sqrt()?;
        Some(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    pub fn from_montgomery(
        &self,
        coordinates: Option<(U, U)>,
    ) -> Result<EllipticCurvePoint<'_, U>> {
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

        if self.cofactor() != U::from_u64(1) {
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

impl<'a, U: UintMont> EllipticCurvePoint<'a, U> {
    pub const fn curve(&self) -> &'a EllipticCurve<U> {
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
            impl<'a, U: UintMont + $trait> $trait for EllipticCurvePoint<'a, U> {
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

impl<U: UintMont> Add for EllipticCurvePoint<'_, U> {
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

impl<U: UintMont> AddAssign for EllipticCurvePoint<'_, U> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<U: UintMont> Neg for EllipticCurvePoint<'_, U> {
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

impl<U: UintMont> Sub for EllipticCurvePoint<'_, U> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: Self) -> Self::Output {
        self + other.neg()
    }
}

impl<U: UintMont> SubAssign for EllipticCurvePoint<'_, U> {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<'a, U: UintMont> Mul<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    type Output = Self;

    fn mul(self, scalar: ModRingElementRef<'a, U>) -> Self::Output {
        assert_eq!(scalar.ring(), self.curve.scalar_field());
        self.mul_uint(scalar.to_uint())
    }
}

impl<'a, U: UintMont> MulAssign<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    fn mul_assign(&mut self, scalar: ModRingElementRef<'a, U>) {
        *self = *self * scalar;
    }
}

impl<'a, U: UintMont> Div<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    type Output = Option<Self>;

    fn div(self, scalar: ModRingElementRef<'a, U>) -> Self::Output {
        scalar.inv().map(|inv| self * inv)
    }
}

impl<'a, U: UintMont> DivAssign<ModRingElementRef<'a, U>> for EllipticCurvePoint<'a, U> {
    fn div_assign(&mut self, scalar: ModRingElementRef<'a, U>) {
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
impl<'a, U: UintMont> ConditionallySelectable for EllipticCurvePoint<'a, U> {
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
impl<U: UintMont> ConstantTimeEq for EllipticCurvePoint<'_, U> {
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

impl<'a, U: 'a + UintMont> CryptoGroup<'a> for EllipticCurve<U> {
    type BaseElement = EllipticCurvePoint<'a, U>;
    type ScalarElement = ModRingElementRef<'a, U>;

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
        named::{
            brainpool_p160r1, brainpool_p512r1, secp192r1, secp224r1, secp256r1, secp384r1,
            secp521r1,
        },
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

    #[test]
    fn test_brainpool_p160r1() {
        let group = brainpool_p160r1();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_brainpool_brainpool_p512r1() {
        let group = brainpool_p512r1();
        test_dh(&group);
        test_schnorr(&group);
    }
}
