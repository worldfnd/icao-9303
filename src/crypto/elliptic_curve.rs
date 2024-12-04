use {
    super::{
        mod_ring::{ModRing, ModRingElementRef, RingRefExt},
        KeyAgreementAlgorithm, PrivateKey, PublicKey,
    },
    crate::asn1::public_key::{EcParameters, FieldId, SubjectPublicKeyInfo},
    anyhow::{anyhow, bail, ensure, Result},
    rand::{CryptoRng, Rng, RngCore},
    std::{
        fmt::{self, Debug, Display, Formatter},
        ops::{Add, AddAssign, Mul, MulAssign, Neg},
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

// The largest prime field we support is 576 bits.
// This covers all the named curves, including secp521r1.
pub type Uint = ruint::Uint<576, 9>;
pub type PrimeField = ModRing<Uint>;
pub type PrimeFieldElement<'a> = ModRingElementRef<'a, Uint>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct EllipticCurve {
    base_field:      PrimeField,
    scalar_field:    PrimeField,
    // Curve parameters in Montgomery form.
    // Ideally we would store as PrimeFieldElement, but that would require a reference
    // to the field which confuses the borrow checker.
    a_monty:         Uint,
    b_monty:         Uint,
    cofactor:        Uint,
    generator_monty: (Uint, Uint),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EllipticCurvePoint<'a> {
    curve:       &'a EllipticCurve,
    coordinates: Coordinates<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Coordinates<'a> {
    Infinity,
    Affine(PrimeFieldElement<'a>, PrimeFieldElement<'a>),
}

pub type EcMonty = Option<(Uint, Uint)>;

impl PrimeField {
    pub fn from_field_id(field_id: &FieldId) -> Result<Self> {
        let modulus = match field_id {
            FieldId::PrimeField { modulus } => modulus.try_into()?,
            _ => bail!("Field ID is not a prime field"),
        };
        Ok(Self::from_modulus(modulus))
    }

    pub fn byte_len(&self) -> usize {
        self.modulus().byte_len()
    }

    /// Implements TR-03111 section 3.1.3 OS2FE procedure.
    ///
    /// Note that it does not have any requirement on the input length and
    /// requires the reader to apply the modular reduction. Note that this
    /// violates the unique encoding property of DER encoding, but we'll
    /// apply the robustness principle and allow it.
    ///
    /// The matching encoding procedure, however, does specify an exact length.
    pub fn os2fe<T: AsRef<[u8]>>(&self, os: T) -> PrimeFieldElement {
        let os = os.as_ref();
        // ensure!(
        //     os.len() != self.modulus.byte_len(),
        //     "OS2FE input length does not match modulus length"
        // );
        // Do modular reduction per TR-03111.
        let mut result = self.zero();
        let base = self.from(Uint::from(256));
        for byte in os {
            result *= base;
            result += self.from(Uint::from(*byte));
        }
        result
    }

    /// TR-03111 section 4.1.1 Algorithm 1
    pub fn random_nonzero(&self, mut rng: impl CryptoRng + RngCore) -> PrimeFieldElement {
        loop {
            let mut value = rng.gen::<Uint>();
            // Zero out the high bits.
            for b in self.modulus().bit_len()..Uint::BITS {
                value.set_bit(b, false);
            }
            if value != Uint::ZERO && value < self.modulus() {
                return self.from(value);
            }
        }
    }
}

impl PrimeFieldElement<'_> {
    pub fn field(&self) -> &PrimeField {
        self.ring()
    }

    /// Implements TR-03111 section 3.1.3 FE2OS procedure.
    pub fn fe2os(&self) -> Vec<u8> {
        let mut result = self.to_uint().to_be_bytes_vec();
        // Trim excess leading zeros.
        result.split_off(result.len() - self.field().byte_len())
    }
}

impl EllipticCurve {
    // TODO: ISO 7816 format (see TR-03111 section 5.1.2)
    pub fn from_parameters(params: &EcParameters) -> Result<Self> {
        ensure!(params.version == 1);

        // TR-03111 only specifies prime field curves.
        // The alternatives would be binary fields and other extension fields.
        // The are some binary field elliptic curves, but they are considered
        // deprecated. I am not aware of any extension field curves in use,
        // other than for ZK-friendliness. ensure!(params.field_id.field_type ==
        // ID_PRIME_FIELD);

        // Construct the base and scalar fields.
        let base_field = PrimeField::from_field_id(&params.field_id)?;
        let scalar_field = PrimeField::from_modulus((&params.order).try_into()?);

        // Ensure they are different fields.
        ensure!(
            base_field != scalar_field,
            "Base and scalar fields must be different"
        );

        // Read the optional cofactor, default to 1.
        let cofactor = (params.cofactor)
            .as_ref()
            .map(Uint::try_from)
            .transpose()?
            .unwrap_or(Uint::from(1));

        // Read curve parameters (TR-03111 section 2.3.1)
        let a = base_field.os2fe(&params.curve.a);
        let b = base_field.os2fe(&params.curve.b);

        // Check non-singular requirement 4a^3 + 27b^2 != 0
        ensure!(
            base_field.from(Uint::from(4)) * a.pow(3) + base_field.from(Uint::from(27)) * b.pow(2)
                != base_field.zero()
        );

        let mut curve = Self {
            base_field,
            scalar_field,
            a_monty: a.as_montgomery(),
            b_monty: b.as_montgomery(),
            cofactor,
            generator_monty: (Uint::ZERO, Uint::ZERO),
        };
        let generator = curve.pt_from_bytes(params.base.as_bytes())?;
        curve.generator_monty = generator.as_monty().unwrap();
        Ok(curve)
    }

    pub fn base_field(&self) -> &PrimeField {
        &self.base_field
    }

    pub fn scalar_field(&self) -> &PrimeField {
        &self.scalar_field
    }

    pub fn cofactor(&self) -> Uint {
        self.cofactor
    }

    pub fn a(&self) -> PrimeFieldElement {
        self.base_field.from_montgomery(self.a_monty)
    }

    pub fn b(&self) -> PrimeFieldElement {
        self.base_field.from_montgomery(self.b_monty)
    }

    pub fn generator(&self) -> EllipticCurvePoint {
        self.pt_from_monty(Some(self.generator_monty)).unwrap()
    }

    pub fn pt_infinity(&self) -> EllipticCurvePoint {
        EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Infinity,
        }
    }

    pub fn pt_from_affine<'a>(
        &'a self,
        (x, y): (PrimeFieldElement<'a>, PrimeFieldElement<'a>),
    ) -> Result<EllipticCurvePoint<'a>> {
        ensure!(x.field() == &self.base_field);
        ensure!(y.field() == &self.base_field);
        self.ensure_valid((x, y))?;
        Ok(EllipticCurvePoint {
            curve:       self,
            coordinates: Coordinates::Affine(x, y),
        })
    }

    pub fn pt_from_monty(&self, monty: EcMonty) -> Result<EllipticCurvePoint> {
        match monty {
            Some((x, y)) => self.pt_from_affine((
                self.base_field.from_montgomery(x),
                self.base_field.from_montgomery(y),
            )),
            None => Ok(self.pt_infinity()),
        }
    }

    /// TR-03111 section 3.2
    pub fn pt_from_bytes(&self, bytes: &[u8]) -> Result<EllipticCurvePoint> {
        ensure!(!bytes.is_empty());
        let fe_len = self.base_field.modulus().byte_len();
        match bytes[0] {
            0x00 => {
                ensure!(bytes.len() == 1);
                Ok(self.pt_infinity())
            }
            0x02 => unimplemented!("Compressed point with y'p = 0"),
            0x03 => unimplemented!("Compressed point with y'p = 1"),
            0x04 => {
                // Uncompressed point
                ensure!(bytes.len() == 1 + 2 * fe_len);
                let x = self.base_field.os2fe(&bytes[1..1 + fe_len]);
                let y = self.base_field.os2fe(&bytes[1 + fe_len..]);
                self.pt_from_affine((x, y))
            }
            _ => bail!("Invalid point encoding"),
        }
    }

    fn ensure_valid<'a>(
        &'a self,
        (x, y): (PrimeFieldElement<'a>, PrimeFieldElement<'a>),
    ) -> Result<()> {
        // Check curve equation y^2 = x^3 + ax + b
        ensure!(
            y.pow(2) == x.pow(3) + self.a() * x + self.b(),
            "Point not on curve."
        );
        if self.cofactor != Uint::from(1) {
            // TODO: Check cofactor. self.order * point == infty
            bail!("Cofactor check unimplemented")
        }
        Ok(())
    }
}

impl<'a> EllipticCurvePoint<'a> {
    pub fn curve(&self) -> &'a EllipticCurve {
        self.curve
    }

    /// TR-03111 section 3.2
    ///
    /// TODO: Compressed?
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.coordinates {
            Coordinates::Infinity => vec![0x00],
            Coordinates::Affine(x, y) => {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(&x.fe2os());
                bytes.extend_from_slice(&y.fe2os());
                bytes
            }
        }
    }

    pub fn as_monty(&self) -> EcMonty {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, y) => Some((x.as_montgomery(), y.as_montgomery())),
        }
    }

    pub fn x(&self) -> Option<PrimeFieldElement<'a>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(x, _) => Some(x),
        }
    }

    pub fn y(&self) -> Option<PrimeFieldElement<'a>> {
        match self.coordinates {
            Coordinates::Infinity => None,
            Coordinates::Affine(_, y) => Some(y),
        }
    }
}

/// Elliptic Curve Key Agreement
/// See TR-03111 section 4.3.1
pub fn ecka<'a>(
    private_key: PrimeFieldElement<'a>,
    public_key: EllipticCurvePoint<'a>,
) -> Result<(EllipticCurvePoint<'a>, Vec<u8>)> {
    let curve = public_key.curve();
    ensure!(private_key.field() == curve.scalar_field());

    let h = curve.cofactor();
    let l = curve.scalar_field().from(h).inv().unwrap();
    let q = h * public_key;
    let s_ab = (private_key * l) * q;
    ensure!(s_ab != curve.pt_infinity());
    let z_ab = s_ab.x().unwrap().fe2os();

    Ok((s_ab, z_ab))
}

impl Display for EllipticCurve {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDH-{}", self.scalar_field().modulus().bit_len())
    }
}

impl KeyAgreementAlgorithm for EllipticCurve {
    fn subject_public_key(&self, pubkey: &SubjectPublicKeyInfo) -> Result<PublicKey> {
        let public = self.pt_from_bytes(pubkey.subject_public_key.raw_bytes())?;
        Ok(PublicKey(public.to_bytes()))
    }

    fn generate_key_pair(&self, rng: &mut dyn super::CryptoCoreRng) -> (PrivateKey, PublicKey) {
        let private = self.scalar_field().random_nonzero(rng);
        let public = self.generator() * private;
        (
            PrivateKey(Box::new(private.as_montgomery())),
            PublicKey(public.to_bytes()),
        )
    }

    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>> {
        let private = self.scalar_field().from_montgomery(
            *private
                .0
                .as_ref()
                .downcast_ref::<Uint>()
                .ok_or(anyhow!("Invalid private key"))?,
        );
        let public = self.pt_from_bytes(&public.0)?;
        let (_, shared) = ecka(private, public)?;
        Ok(shared)
    }
}

macro_rules! forward_fmt {
    ($($type:ty),+) => {
        $(
            impl<> $type for EllipticCurvePoint<'_> {
                fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                    match self.coordinates {
                        Coordinates::Infinity => write!(f, "Infinity"),
                        Coordinates::Affine(x, y) => {
                            write!(f, "(")?;
                            <PrimeFieldElement<'_> as $type>::fmt(&x, f)?;
                            write!(f, ", ")?;
                            <PrimeFieldElement<'_> as $type>::fmt(&y, f)?;
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

impl Add for EllipticCurvePoint<'_> {
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
                        let lambda = (self.curve.base_field.from(Uint::from(3)) * x1.pow(2)
                            + self.curve.a())
                            / (self.curve.base_field.from(Uint::from(2)) * y1);
                        let lambda = lambda.unwrap();
                        let x3 = lambda.pow(2) - self.curve.base_field.from(Uint::from(2)) * x1;
                        let y3 = lambda * (x1 - x3) - y1;
                        EllipticCurvePoint {
                            curve:       self.curve,
                            coordinates: Coordinates::Affine(x3, y3),
                        }
                    } else {
                        // Point at infinity
                        self.curve.pt_infinity()
                    }
                } else {
                    let lambda = (y2 - y1) / (x2 - x1);
                    let lambda = lambda.unwrap();
                    let x3 = lambda.pow(2) - x1 - x2;
                    let y3 = lambda * (x1 - x3) - y1;
                    self.curve.pt_from_affine((x3, y3)).unwrap()
                }
            }
        }
    }
}

impl AddAssign for EllipticCurvePoint<'_> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Neg for EllipticCurvePoint<'_> {
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

impl Mul<Uint> for EllipticCurvePoint<'_> {
    type Output = Self;

    fn mul(mut self, scalar: Uint) -> Self::Output {
        let mut result = self.curve.pt_infinity();
        for i in 0..Uint::BITS {
            result.conditional_assign(&(result + self), scalar.bit_ct(i));
            self += self;
        }
        result
    }
}

impl<'a> Mul<EllipticCurvePoint<'a>> for Uint {
    type Output = EllipticCurvePoint<'a>;

    fn mul(self, point: EllipticCurvePoint<'a>) -> Self::Output {
        point * self
    }
}

impl MulAssign<Uint> for EllipticCurvePoint<'_> {
    fn mul_assign(&mut self, scalar: Uint) {
        *self = *self * scalar;
    }
}

impl<'a> Mul<PrimeFieldElement<'a>> for EllipticCurvePoint<'_> {
    type Output = Self;

    fn mul(self, scalar: PrimeFieldElement<'a>) -> Self::Output {
        self * scalar.to_uint()
    }
}

impl<'a> Mul<EllipticCurvePoint<'a>> for PrimeFieldElement<'_> {
    type Output = EllipticCurvePoint<'a>;

    fn mul(self, point: EllipticCurvePoint<'a>) -> Self::Output {
        point * self
    }
}

impl<'a> MulAssign<PrimeFieldElement<'a>> for EllipticCurvePoint<'_> {
    fn mul_assign(&mut self, scalar: PrimeFieldElement<'a>) {
        *self = *self * scalar;
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
impl<'a> ConditionallySelectable for EllipticCurvePoint<'a> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        assert_eq!(a.curve, b.curve);
        use Coordinates::*;
        let coordinates = match (&a.coordinates, &b.coordinates) {
            (Infinity, Infinity) => Infinity,
            (Affine(ax, ay), Affine(bx, by)) => Affine(
                PrimeFieldElement::<'a>::conditional_select(ax, bx, choice),
                PrimeFieldElement::<'a>::conditional_select(ay, by, choice),
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
impl ConstantTimeEq for EllipticCurvePoint<'_> {
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
