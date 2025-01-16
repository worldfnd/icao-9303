use {
    super::{AnyAlgorithmIdentifier, DigestAlgorithmIdentifier, DigestAlgorithmParameters},
    der::{
        asn1::{Int, Null, ObjectIdentifier as Oid},
        Any, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence, ValueOrd,
        Writer,
    },
    std::cmp::Ordering,
};

pub const ID_MGFA_MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");
pub const ID_SIG_ECDSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10045.4.1");
pub const ID_SIG_ECDSA_SHA224: Oid = Oid::new_unwrap("1.2.840.10045.4.3.1");
pub const ID_SIG_ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
pub const ID_SIG_ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
pub const ID_SIG_ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
pub const ID_SIG_RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
pub const ID_SIG_RSASSA_PKCS1_SHA1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");
pub const ID_SIG_RSASSA_PKCS1_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
pub const ID_SIG_RSASSA_PKCS1_SHA384: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
pub const ID_SIG_RSASSA_PKCS1_SHA512: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Sequence)]
pub struct EcdsaSigValue {
    pub r: Int,
    pub s: Int,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SignatureAlgorithmIdentifier {
    EcdsaSha1,
    EcdsaSha224,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaPss(RsaPssParameters),
    Unknown(AnyAlgorithmIdentifier),
}

impl Sequence<'_> for SignatureAlgorithmIdentifier {}

impl ValueOrd for SignatureAlgorithmIdentifier {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl EncodeValue for SignatureAlgorithmIdentifier {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Unknown(any) => any.value_len(),
            _ => todo!(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Unknown(any) => any.encode(writer),
            _ => todo!(),
        }
    }
}

impl<'a> DecodeValue<'a> for SignatureAlgorithmIdentifier {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        Ok(match oid {
            ID_SIG_ECDSA_SHA1 => {
                Null::decode(reader)?;
                Self::EcdsaSha1
            }
            ID_SIG_ECDSA_SHA224 => Self::EcdsaSha224,
            ID_SIG_ECDSA_SHA256 => Self::EcdsaSha256,
            ID_SIG_ECDSA_SHA384 => Self::EcdsaSha384,
            ID_SIG_ECDSA_SHA512 => Self::EcdsaSha512,
            ID_SIG_RSASSA_PSS => Self::RsaPss(RsaPssParameters::decode(reader)?),
            ID_SIG_RSASSA_PKCS1_SHA1 => {
                Null::decode(reader)?;
                Self::RsaPkcsSha1
            }
            ID_SIG_RSASSA_PKCS1_SHA256 => {
                Null::decode(reader)?;
                Self::RsaPkcsSha256
            }
            ID_SIG_RSASSA_PKCS1_SHA384 => {
                Null::decode(reader)?;
                Self::RsaPkcsSha384
            }
            ID_SIG_RSASSA_PKCS1_SHA512 => {
                Null::decode(reader)?;
                Self::RsaPkcsSha512
            }
            _ => Self::Unknown(AnyAlgorithmIdentifier {
                algorithm:  oid,
                parameters: Option::<Any>::decode(reader)?,
            }),
        })
    }
}

// RFC 4055 3.1:
// RSASSA-PSS-params  ::=  SEQUENCE  {
//     hashAlgorithm      [0] HashAlgorithm DEFAULT
//                               sha1Identifier,
//     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
//                               mgf1SHA1Identifier,
//     saltLength         [2] INTEGER DEFAULT 20,
//     trailerField       [3] INTEGER DEFAULT 1 }
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct RsaPssParameters {
    #[asn1(context_specific = "0", default = "default_hash_algorithm")]
    pub hash_algorithm:     DigestAlgorithmIdentifier,
    #[asn1(context_specific = "1", default = "default_mask_gen_algorithm")]
    pub mask_gen_algorithm: MaskGenAlgorithm,
    #[asn1(context_specific = "2", default = "default_salt_length")]
    pub salt_length:        Int,
    #[asn1(context_specific = "3", default = "default_trailer_field")]
    pub trailer_field:      Int,
}

fn default_hash_algorithm() -> DigestAlgorithmIdentifier {
    DigestAlgorithmIdentifier::Sha1(DigestAlgorithmParameters::Absent)
}

fn default_mask_gen_algorithm() -> MaskGenAlgorithm {
    MaskGenAlgorithm::Mgf1(DigestAlgorithmIdentifier::Sha1(
        DigestAlgorithmParameters::Absent,
    ))
}

fn default_salt_length() -> Int {
    Int::new(&[20]).unwrap()
}

fn default_trailer_field() -> Int {
    Int::new(&[1]).unwrap()
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MaskGenAlgorithm {
    Mgf1(DigestAlgorithmIdentifier),
    Unknown(AnyAlgorithmIdentifier),
}

impl Sequence<'_> for MaskGenAlgorithm {}

impl ValueOrd for MaskGenAlgorithm {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl EncodeValue for MaskGenAlgorithm {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Mgf1(_) => todo!(),
            Self::Unknown(any) => any.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Mgf1(_) => todo!(),
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for MaskGenAlgorithm {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        Ok(match oid {
            ID_MGFA_MGF1 => Self::Mgf1(DigestAlgorithmIdentifier::decode(reader)?),
            _ => Self::Unknown(AnyAlgorithmIdentifier {
                algorithm:  oid,
                parameters: Option::<Any>::decode(reader)?,
            }),
        })
    }
}

impl TryFrom<&spki::AlgorithmIdentifierOwned> for SignatureAlgorithmIdentifier {
    type Error = anyhow::Error;
    fn try_from(id: &spki::AlgorithmIdentifierOwned) -> anyhow::Result<Self, anyhow::Error> {
        Ok(Self::from_der(&id.to_der()?)?)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    #[test]
    fn test_decode_signature_algorithm_rsa_ssa_pss() {
        let der_params_w_mgf_sha1 = hex!("300d06092a864886f70d01010a3000");
        let der_params_w_mgf_sha256 = hex!("303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a203020120");
        let der_params_w_mgf_sha384 = hex!("303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a203020130");
        let der_params_w_mgf_sha512 = hex!("303d06092a864886f70d01010a3030a00d300b0609608648016503040203a11a301806092a864886f70d010108300b0609608648016503040203a203020140");
        SignatureAlgorithmIdentifier::from_der(&der_params_w_mgf_sha1).unwrap();
        SignatureAlgorithmIdentifier::from_der(&der_params_w_mgf_sha256).unwrap();
        SignatureAlgorithmIdentifier::from_der(&der_params_w_mgf_sha384).unwrap();
        SignatureAlgorithmIdentifier::from_der(&der_params_w_mgf_sha512).unwrap();
    }

    #[test]
    fn test_decode_signature_algorithm_rsa_ssa_pkc1_with_sha256() {
        let hex = hex!("300d06092a864886f70d01010b0500");
        let algo = SignatureAlgorithmIdentifier::from_der(&hex).unwrap();
        assert_eq!(algo, SignatureAlgorithmIdentifier::RsaPkcsSha256);
    }

    #[test]
    fn test_decode_signature_algorithm_ecdsa_with_sha1() {
        let hex = hex!("300b06072a8648ce3d04010500");
        let algo = SignatureAlgorithmIdentifier::from_der(&hex).unwrap();
        assert_eq!(algo, SignatureAlgorithmIdentifier::EcdsaSha1);
    }

    #[test]
    fn test_decode_signature_algorithm_ecdsa_with_sha256() {
        let hex = hex!("300a06082a8648ce3d040302");
        let algo = SignatureAlgorithmIdentifier::from_der(&hex).unwrap();
        assert_eq!(algo, SignatureAlgorithmIdentifier::EcdsaSha256);
    }
}
