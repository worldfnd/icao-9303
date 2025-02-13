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
mod named_curves;
mod pki;
mod public_key;
mod rsa;
mod signature;
pub mod trust;

use {
    self::{ecdsa::ECPublicKey, named_curves::*},
    crate::asn1::public_key_info::{ECAlgoParameters, EcPublicKeyInfo, SubjectPublicKeyInfo},
    anyhow::{bail, Result},
    rand::{CryptoRng, RngCore},
    std::any::Any,
};
pub use {codec::Codec, key_agreement::KeyAgreementAlgorithm, public_key::PublicKey};

pub trait CryptoCoreRng: CryptoRng + RngCore {}

impl<T> CryptoCoreRng for T where T: CryptoRng + RngCore {}

/// Opaque wrapper for private keys.
pub struct PrivateKey(Box<dyn Any>);

impl SubjectPublicKeyInfo {
    /// Returns the KeyAgreementAlgorithm and public key.
    pub fn to_algorithm_public_key(&self) -> Result<(Box<dyn KeyAgreementAlgorithm>, PublicKey)> {
        match self {
            SubjectPublicKeyInfo::DH(_info) => todo!(),
            SubjectPublicKeyInfo::EC((params, info)) => create_ec_key_by_size(params, info),
            _ => bail!("Unknown key agreement algorithm."),
        }
    }
}

use ruint::{aliases::*, Uint};
type U224 = Uint<224, 4>;
type U521 = Uint<521, 9>;

fn create_ec_key_by_size(
    params: &ECAlgoParameters,
    info: &EcPublicKeyInfo,
) -> Result<(Box<dyn KeyAgreementAlgorithm>, PublicKey)> {
    match params {
        ECAlgoParameters::NamedCurve(oid) => match *oid {
            ID_SEC_P521R1 => {
                let key = ECPublicKey::<U521>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_BRAINPOOL_P512R1 => {
                let key = ECPublicKey::<U512>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_SEC_P384R1 | ID_BRAINPOOL_P384R1 => {
                let key = ECPublicKey::<U384>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_SEC_P256R1 | ID_BRAINPOOL_P256R1 => {
                let key = ECPublicKey::<U256>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_SEC_P224R1 | ID_BRAINPOOL_P224R1 => {
                let key = ECPublicKey::<U224>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_SEC_P192R1 | ID_BRAINPOOL_P192R1 => {
                let key = ECPublicKey::<U192>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_BRAINPOOL_P320R1 => {
                let key = ECPublicKey::<U320>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            ID_BRAINPOOL_P160R1 => {
                let key = ECPublicKey::<U160>::try_from((params.clone(), info.clone()))?;
                let curve = key.curve.clone();
                Ok((Box::new(curve), Box::new(key)))
            }
            _ => bail!("Unsupported curve OID: {}", oid),
        },
        ECAlgoParameters::EcParameters(eparams) => {
            match &eparams.field_id {
                crate::asn1::public_key_info::FieldId::PrimeField { modulus } => {
                    use crate::crypto::mod_ring::UintExp;
                    let size = U521::try_from(modulus)?.significant_bits(); // TODO fix
                    println!("size: {size}");
                    match size {
                        521 => {
                            let key =
                                ECPublicKey::<U521>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        512 => {
                            let key =
                                ECPublicKey::<U512>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        384 => {
                            let key =
                                ECPublicKey::<U384>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        320 => {
                            let key =
                                ECPublicKey::<U320>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        256 => {
                            let key =
                                ECPublicKey::<U256>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        224 => {
                            let key =
                                ECPublicKey::<U224>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        192 => {
                            let key =
                                ECPublicKey::<U192>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        160 => {
                            let key =
                                ECPublicKey::<U160>::try_from((params.clone(), info.clone()))?;
                            let curve = key.curve.clone();
                            Ok((Box::new(curve), Box::new(key)))
                        }
                        _ => bail!("Unsupported field size: {}", size),
                    }
                }
                crate::asn1::public_key_info::FieldId::Unknown(any) => {
                    bail!("Unsupported field type: {}", any.field_type)
                }
            }
        }
        ECAlgoParameters::ImplicitlyCA(_) => bail!("ImplicitlyCA parameters not supported"),
    }
}
