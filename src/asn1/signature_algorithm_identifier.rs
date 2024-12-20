use {
    super::AnyAlgorithmIdentifier,
    der::{
        asn1::{Int, Null, ObjectIdentifier as Oid},
        Any, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Result, Sequence, ValueOrd,
        Writer,
    },
    std::cmp::Ordering,
};

pub const ID_SIG_RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SignatureAlgorithmIdentifier {
    Rsa(RsaSsaPssParameters),
    Unknown(AnyAlgorithmIdentifier),
}

// TODO verify fields below
// RFC 4055 3.1:
// RSASSA-PSS-params  ::=  SEQUENCE  {
//     hashAlgorithm      [0] HashAlgorithm DEFAULT
//                               sha1Identifier,
//     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
//                               mgf1SHA1Identifier,
//     saltLength         [2] INTEGER DEFAULT 20,
//     trailerField       [3] INTEGER DEFAULT 1
//  }
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct RsaSsaPssParameters {
    pub hash_algorithm:     AnyAlgorithmIdentifier,
    pub mask_gen_algorithm: AnyAlgorithmIdentifier,
    pub salt_length:        Int,
    pub trailer_field:      Int,
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
            Self::Rsa(_) => ID_SIG_RSASSA_PSS.encoded_len()? + Null.encoded_len()?,
            Self::Unknown(any) => any.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Rsa(_) => {
                ID_SIG_RSASSA_PSS.encode(writer)?;
                Null.encode(writer)
            }
            Self::Unknown(any) => any.encode(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for SignatureAlgorithmIdentifier {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> Result<Self> {
        let oid = Oid::decode(reader)?;
        dbg!(&oid);
        Ok(match oid {
            ID_SIG_RSASSA_PSS => Self::Rsa(RsaSsaPssParameters::decode(reader)?),
            _ => Self::Unknown(AnyAlgorithmIdentifier {
                algorithm:  oid,
                parameters: Option::<Any>::decode(reader)?,
            }),
        })
    }
}
