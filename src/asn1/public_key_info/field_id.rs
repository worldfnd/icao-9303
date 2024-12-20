use {
    der::{
        asn1::{Int, ObjectIdentifier as Oid},
        Any, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence, ValueOrd,
        Writer,
    },
    std::cmp::Ordering,
};

pub const ID_PRIME_FIELD: Oid = Oid::new_unwrap("1.2.840.10045.1.1");

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum FieldId {
    PrimeField { modulus: Int },
    Unknown(AnyFieldId),
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AnyFieldId {
    pub field_type: Oid,
    pub parameters: Any,
}

impl Sequence<'_> for FieldId {}

impl ValueOrd for FieldId {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl EncodeValue for FieldId {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::PrimeField { modulus } => {
                ID_PRIME_FIELD.encoded_len()? + modulus.encoded_len()?
            }
            Self::Unknown(any) => any.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::PrimeField { modulus } => {
                ID_PRIME_FIELD.encode(writer)?;
                modulus.encode(writer)
            }
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for FieldId {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        Ok(match oid {
            ID_PRIME_FIELD => Self::PrimeField {
                modulus: Int::decode(reader)?,
            },
            _ => Self::Unknown(AnyFieldId {
                field_type: oid,
                parameters: Any::decode(reader)?,
            }),
        })
    }
}
