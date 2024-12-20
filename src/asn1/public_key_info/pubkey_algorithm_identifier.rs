use {
    super::{super::AnyAlgorithmIdentifier, DhAlgoParameters, ECAlgoParameters},
    der::{
        asn1::{Null, ObjectIdentifier as Oid},
        Any, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence, ValueOrd,
        Writer,
    },
    std::cmp::Ordering,
};

// See RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
pub const ID_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");

// See RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
// See TR-03111
// ANSI X9.62 1.2.840.10045
// public key 2
// elliptic curve 1
pub const ID_EC: Oid = Oid::new_unwrap("1.2.840.10045.2.1");

/// PKCS 3
///
/// https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf
pub const ID_DH: Oid = Oid::new_unwrap("1.2.840.113549.1.3.1");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PubkeyAlgorithmIdentifier {
    Rsa,
    Ec(ECAlgoParameters),
    Dh(DhAlgoParameters),
    Unknown(AnyAlgorithmIdentifier),
}

impl Sequence<'_> for PubkeyAlgorithmIdentifier {}

impl ValueOrd for PubkeyAlgorithmIdentifier {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl EncodeValue for PubkeyAlgorithmIdentifier {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Rsa => ID_RSA.encoded_len()? + Null.encoded_len()?,
            Self::Ec(params) => ID_EC.encoded_len()? + params.encoded_len()?,
            Self::Dh(params) => ID_DH.encoded_len()? + params.encoded_len()?,
            Self::Unknown(any) => any.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Rsa => {
                ID_RSA.encode(writer)?;
                Null.encode(writer)
            }
            Self::Ec(params) => {
                ID_EC.encode(writer)?;
                params.encode(writer)
            }
            Self::Dh(params) => {
                ID_DH.encode(writer)?;
                params.encode(writer)
            }
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for PubkeyAlgorithmIdentifier {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        Ok(match oid {
            ID_RSA => {
                Null::decode(reader)?;
                Self::Rsa
            }
            ID_EC => Self::Ec(ECAlgoParameters::decode(reader)?),
            ID_DH => Self::Dh(DhAlgoParameters::decode(reader)?),
            _ => Self::Unknown(AnyAlgorithmIdentifier {
                algorithm:  oid,
                parameters: Option::<Any>::decode(reader)?,
            }),
        })
    }
}
