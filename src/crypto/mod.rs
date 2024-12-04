//! Implements the required cryptography.
//!
//! Primarily based on TR-03111.

mod diffie_hellman;
mod elliptic_curve;
pub mod mod_ring;
mod named_curves;
mod named_fields;
mod signature;

pub use self::{
    diffie_hellman::ModPGroup,
    elliptic_curve::{ecka, EllipticCurve, EllipticCurvePoint},
};
use {
    crate::asn1::public_key::{ECAlgoParameters, PubkeyAlgorithmIdentifier, SubjectPublicKeyInfo},
    anyhow::{bail, ensure, Result},
    der::asn1::OctetString,
    rand::{CryptoRng, RngCore},
    ruint::Uint,
    std::{
        any::Any,
        fmt::{Debug, Display},
    },
};

pub trait CryptoCoreRng: CryptoRng + RngCore {}

impl<T> CryptoCoreRng for T where T: CryptoRng + RngCore {}

/// Opaque wrapper for public keys.
///
/// Derefs as a byte slice.
pub struct PublicKey(Vec<u8>);

/// Opaque wrapper for private keys.
pub struct PrivateKey(Box<dyn Any>);

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
            PubkeyAlgorithmIdentifier::Dh(params) => Box::new(ModPGroup::from_parameters(params)?),
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
