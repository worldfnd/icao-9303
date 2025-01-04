//! Implements discrete-logarithm hard groups for cryptographic operations.

mod elliptic_curve;
mod modp_group;
mod mul_group;
pub mod named;

pub use self::elliptic_curve::{EllipticCurve, EllipticCurvePoint};
use {
    super::CryptoCoreRng,
    num_traits::Inv,
    std::{
        fmt::Debug,
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

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

/// Test the Diffie-Hellman key exchange.
#[cfg(test)]
fn test_dh<'s>(group: &'s impl CryptoGroup<'s>) {
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
fn test_schnorr<'s>(group: &'s impl CryptoGroup<'s>) {
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
