//! Implements the required cryptography.
//!
//! Primarily based on TR-03111.

pub mod certificate;
pub mod cipher;
mod codec;
mod dh;
pub mod ecdsa;
pub mod groups;
pub mod key_agreement;
pub mod mod_ring;
mod pki;
mod public_key;
mod rsa;
mod signature;
pub mod trust;

use {
    crate::asn1::{
        emrtd::security_info::{PaceInfo, StandardizedDomainParameter},
        public_key_info::SubjectPublicKeyInfo,
    },
    anyhow::{anyhow, bail, ensure, Result},
    der::asn1::OctetString,
    rand::{CryptoRng, RngCore},
    ruint::Uint,
    std::any::Any,
};
pub use {
    codec::{BsiTr031111Codec, BufCodecParent, Codec},
    key_agreement::KeyAgreementAlgorithm,
    public_key::PublicKey,
};

pub trait CryptoCoreRng: CryptoRng + RngCore {}

impl<T> CryptoCoreRng for T where T: CryptoRng + RngCore {}

///// Opaque wrapper for public keys.
/////
///// Derefs as a byte slice.
// pub struct PublicKey(Vec<u8>);

/// Opaque wrapper for private keys.
pub struct PrivateKey(pub Box<dyn Any>);

// impl AsRef<[u8]> for PublicKey {
//    fn as_ref(&self) -> &[u8] {
//        self.0.as_ref()
//    }
//}

type U521 = ruint::Uint<521, 9>;
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

impl PaceInfo {
    pub fn kaa(&self) -> Result<Box<dyn KeyAgreementAlgorithm>> {
        let id = self
            .parameter_id
            .ok_or_else(|| anyhow!("PaceInfo does not have parameterId set"))?;
        match id.into() {
            StandardizedDomainParameter::EcBrainpoolp256r1 => {
                Ok(Box::new(groups::named::brainpool_p256r1_l()))
            }
            StandardizedDomainParameter::EcBrainpoolp320r1 => {
                Ok(Box::new(groups::named::brainpool_p320r1_l()))
            }
            _ => todo!("{id}"),
        }
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
