mod field_id;
mod pubkey_algorithm_identifier;

pub use self::{field_id::FieldId, pubkey_algorithm_identifier::PubkeyAlgorithmIdentifier};
use der::{
    asn1::{BitString, Int, Null, ObjectIdentifier as Oid, OctetString},
    Choice, Sequence, ValueOrd,
};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SubjectPublicKeyInfo {
    Rsa(RsaPublicKeyInfo),
    Unknown(AnySubjectPublicKeyInfo),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AnySubjectPublicKeyInfo {
    pub algorithm:          AnyAlgorithmIdentifier,
    pub subject_public_key: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct RsaPublicKeyInfo {
    pub modulus:         Int,
    pub public_exponent: Int,
}

/// Diffie-Hellman Mod-P Group Parameters.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct DhAlgoParameters {
    pub prime:                Int,
    pub base:                 Int,
    pub private_value_length: Option<u64>,
}

/// Elliptic Curve Algorithm Parameters.
///
/// **Note**: This deviates from RFC 5480 by allowing for explicit
/// parameters using `EcParameters` in addition to named curves. This
/// is used by at least some Dutch eMRTDs.
///
/// [TR-03111] `Parameters`
/// Details on parameters in [TR-03111]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Choice, ValueOrd)]
pub enum ECAlgoParameters {
    EcParameters(EcParameters),
    NamedCurve(Oid),
    ImplicitlyCA(Null),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct EcParameters {
    pub version:  u64,
    pub field_id: FieldId,
    pub curve:    Curve,
    pub base:     ECPoint,
    pub order:    Int,
    pub cofactor: Option<Int>,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct Curve {
    pub a:    FieldElement,
    pub b:    FieldElement,
    pub seed: Option<BitString>,
}

pub type FieldElement = OctetString;

pub type ECPoint = OctetString;

impl Sequence<'_> for SubjectPublicKeyInfo {}

impl ValueOrd for SubjectPublicKeyInfo {
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
            Self::Rsa => ID_RSA.encoded_len() + Null.encoded_len()?,
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
