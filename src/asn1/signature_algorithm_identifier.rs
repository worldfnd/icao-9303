use {
    super::{AnyAlgorithmIdentifier, DigestAlgorithmIdentifier, DigestAlgorithmParameters},
    der::{
        asn1::{Int, ObjectIdentifier as Oid},
        Any, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence, ValueOrd,
        Writer,
    },
    std::cmp::Ordering,
};

pub const ID_SIG_RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
pub const ID_MGFA_MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SignatureAlgorithmIdentifier {
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
            Self::RsaPss(_) => todo!(),
            Self::Unknown(any) => any.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::RsaPss(_) => todo!(),
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for SignatureAlgorithmIdentifier {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        Ok(match oid {
            ID_SIG_RSASSA_PSS => Self::RsaPss(RsaPssParameters::decode(reader)?),
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
}
