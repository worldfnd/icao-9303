//! Implements the required cryptography.
//!
//! Primarily based on TR-03111.

mod elliptic_curve;
pub mod mod_ring;
pub mod modp_group;
mod mul_group;
mod named_curves;
mod named_fields;
mod signature;

pub use self::elliptic_curve::{ecka, EllipticCurve, EllipticCurvePoint};
use {
    crate::asn1::public_key::{ECAlgoParameters, PubkeyAlgorithmIdentifier, SubjectPublicKeyInfo},
    anyhow::{bail, ensure, Result},
    der::asn1::OctetString,
    num_traits::Inv,
    rand::{CryptoRng, RngCore},
    ruint::Uint,
    std::{
        any::Any,
        fmt::{Debug, Display},
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

pub trait CryptoCoreRng: CryptoRng + RngCore {}

/// An algebraic group, written additively.
pub trait GroupElement:
    Debug
    + Clone
    + Copy
    + PartialEq
    + Eq
    + Neg
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + AddAssign
    + SubAssign
{
}

/// An algebraic ring.
pub trait RingElement:
    GroupElement
    + Mul<Self, Output = Self>
    + MulAssign
    + Div<Self, Output = Option<Self>>
    + Inv<Output = Option<Self>>
{
}

/// A group with a generator and a scalar ring, written additively.
pub trait CryptoGroup<'s> {
    type BaseElement: 's
        + GroupElement
        + Mul<Self::ScalarElement, Output = Self::BaseElement>
        + MulAssign<Self::ScalarElement>
        + Div<Self::ScalarElement, Output = Option<Self::BaseElement>>
        + DivAssign<Self::ScalarElement>;
    type ScalarElement: 's + RingElement;

    /// Returns the generator of the group.
    fn generator(&'s self) -> Self::BaseElement;

    /// Returns a cryptographically random scalar.
    /// This is used for key generation and should meet the security
    /// requirements of the group.
    fn random_scalar(&'s self, rng: &mut dyn CryptoCoreRng) -> Self::ScalarElement;
}

impl<T> CryptoCoreRng for T where T: CryptoRng + RngCore {}

impl<T> GroupElement for T where
    T: Debug
        + Clone
        + Copy
        + PartialEq
        + Eq
        + Neg
        + Add<Self, Output = Self>
        + Sub<Self, Output = Self>
        + AddAssign
        + SubAssign
{
}

impl<T> RingElement for T where
    T: GroupElement
        + Mul<Self, Output = Self>
        + MulAssign
        + Div<Output = Option<Self>>
        + Inv<Output = Option<Self>>
{
}

/// Opaque wrapper for public keys.
///
/// Derefs as a byte slice.
pub struct PublicKey(Vec<u8>);

/// Opaque wrapper for private keys.
pub struct PrivateKey(Box<dyn Any>);

pub trait DiffieHellman {
    fn generate_private_key(&self, rng: &mut dyn CryptoCoreRng) -> Vec<u8>;
    fn private_to_public(&self, private: &[u8]) -> Result<Vec<u8>>;
    fn shared_secret(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>>;
}

/// Object safe trait for key agreement algorithms
pub trait KeyAgreementAlgorithm: Display + Debug {
    fn subject_public_key(&self, pubkey: &SubjectPublicKeyInfo) -> Result<PublicKey>;
    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey, PublicKey);
    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>>;
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SubjectPublicKeyInfo {
    /// Returns the KeyAgreementAlgorithm and public key.
    pub fn to_algorithm_public_key(&self) -> Result<(Box<dyn KeyAgreementAlgorithm>, PublicKey)> {
        let algo: Box<dyn KeyAgreementAlgorithm> = match &self.algorithm {
            PubkeyAlgorithmIdentifier::Dh(params) => todo!(), /* Box::new(ModPGroup::from_parameters(params)?), */
            PubkeyAlgorithmIdentifier::Ec(ec) => match ec {
                ECAlgoParameters::EcParameters(params) => {
                    Box::new(EllipticCurve::from_parameters(params)?)
                }
                ECAlgoParameters::NamedCurve(_) => bail!("Unknown named curve"),
                ECAlgoParameters::ImplicitlyCA(_) => bail!("Implicit CA not implemented"),
            },
            _ => bail!("Unknown key agreement algorithm."),
        };
        let public = algo.subject_public_key(self)?;
        Ok((algo, public))
    }
}

pub fn parse_uint_os<const B: usize, const L: usize>(os: &OctetString) -> Result<Uint<B, L>> {
    // Get twos-complement big-endian bytes
    let big_endian = os.as_bytes();

    // TODO: Length should be exactly length of modulus in bytes.

    // Ensure the number is not too large
    ensure!(big_endian.len() <= 40, "Modulus is too large");

    // Zero extend to 320 bits
    let mut zero_extended = [0; 40];
    zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

    // Parse as Uint
    let uint = Uint::from_be_slice(&zero_extended);
    Ok(uint)
}

/// Test the Diffie-Hellman key exchange.
#[cfg(test)]
fn test_dh<'s, G: CryptoGroup<'s>>(group: &'s G) {
    let rng = &mut rand::thread_rng();
    let alice_private = group.random_scalar(rng);
    let bob_private = group.random_scalar(rng);

    let alice_public = group.generator() * alice_private;
    let bob_public = group.generator() * bob_private;

    let alice_shared = bob_public * alice_private;
    let bob_shared = alice_public * bob_private;

    assert_eq!(alice_shared, bob_shared);
}

/// Test the Schnorr signature scheme.
#[cfg(test)]
fn test_schnorr<'s, G: CryptoGroup<'s>>(group: &'s G) {
    let rng = &mut rand::thread_rng();

    let private = group.random_scalar(rng);
    let public = group.generator() * private;

    // Create a signature
    let nonce = group.random_scalar(rng); // Should be hash(private, message)
    let commitment = group.generator() * nonce;
    let e = group.random_scalar(rng); // Should be hash(commitment, public, message)
    let s = nonce - e * private;

    // Verify the signature (e, s)
    let recovered = group.generator() * s + public * e;
    assert_eq!(recovered, commitment);
    // Would check e == hash(commitment, public, message)

    // Verify the alternative signature (commitment, s)
    // Would compute e = hash(commitment, public, message)
    let recovered = ((commitment - group.generator() * s) / e).unwrap();
    assert_eq!(recovered, public);
}
