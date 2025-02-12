//! Implements the required cryptography.
//!
//! Primarily based on TR-03111.

pub mod certificate;
mod codec;
mod dh;
mod ecdsa;
pub mod groups;
mod key_agreement;
pub mod mod_ring;
mod pki;
mod public_key;
mod rsa;
mod signature;
pub mod trust;

use {
    crate::asn1::public_key_info::SubjectPublicKeyInfo,
    anyhow::{bail, Result},
    rand::{CryptoRng, RngCore},
    std::any::Any,
};
pub use {codec::Codec, key_agreement::KeyAgreementAlgorithm, public_key::PublicKey};

pub trait CryptoCoreRng: CryptoRng + RngCore {}

impl<T> CryptoCoreRng for T where T: CryptoRng + RngCore {}

/// Opaque wrapper for private keys.
pub struct PrivateKey(Box<dyn Any>);

pub mod uint {
    use ruint::{
        aliases::{U2048, U256, U4096},
        Uint,
    };
    type U521 = Uint<521, 9>;
    pub type EcUint = U521;
    pub type DhUint = U2048;
    pub type DhsUint = U256;
    pub type RsaUint = U4096;
}

impl SubjectPublicKeyInfo {
    /// Returns the KeyAgreementAlgorithm and public key.
    pub fn to_algorithm_public_key(&self) -> Result<(Box<dyn KeyAgreementAlgorithm>, PublicKey)> {
        let res: (Box<dyn KeyAgreementAlgorithm>, PublicKey) = match &self {
            SubjectPublicKeyInfo::DH(_info) => todo!(),
            SubjectPublicKeyInfo::EC(info) => {
                let key = ecdsa::ECPublicKey::try_from(info.clone())?;
                let curve = key.curve.clone();
                (Box::new(curve), PublicKey::EC(key))
            }
            _ => bail!("Unknown key agreement algorithm."),
        };
        Ok(res)
    }
}
