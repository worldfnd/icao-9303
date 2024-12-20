mod field_id;
mod pubkey_algorithm_identifier;

pub use self::{field_id::FieldId, pubkey_algorithm_identifier::PubkeyAlgorithmIdentifier};
use {
    crate::asn1::AnyAlgorithmIdentifier,
    der::{
        asn1::{BitString, Int, Null, ObjectIdentifier as Oid, OctetString},
        Choice, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence,
        ValueOrd, Writer,
    },
    std::cmp::Ordering,
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
    pub subject_public_key: BitString,
    // pub modulus: Int,
    // pub public_exponent: Int,
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

impl SubjectPublicKeyInfo {
    pub fn bit_len(&self) -> usize {
        match self {
            Self::Rsa(info) => info.subject_public_key.bit_len(),
            Self::Unknown(info) => info.subject_public_key.bit_len(),
        }
    }
}

impl Sequence<'_> for SubjectPublicKeyInfo {}

impl ValueOrd for SubjectPublicKeyInfo {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl EncodeValue for SubjectPublicKeyInfo {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Rsa(_info) => todo!(),
            Self::Unknown(info) => info.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Rsa(_info) => todo!(),
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let algo = PubkeyAlgorithmIdentifier::decode(reader)?;
        let subject_public_key = BitString::decode(reader)?;
        Ok(match algo {
            PubkeyAlgorithmIdentifier::Rsa => Self::Rsa(RsaPublicKeyInfo { subject_public_key }),
            PubkeyAlgorithmIdentifier::Unknown(id) => Self::Unknown(AnySubjectPublicKeyInfo {
                algorithm: id,
                subject_public_key,
            }),
            _ => todo!(),
        })
    }
}
