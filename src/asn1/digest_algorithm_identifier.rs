use {
    super::AnyAlgorithmIdentifier,
    der::{
        asn1::{Null, ObjectIdentifier as Oid},
        Any, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Length, Reader, Result, Sequence,
        Tag, Tagged, Writer,
    },
    sha1::Digest,
    std::fmt::{self, Display, Formatter},
};

// Hash algorithms
// See: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
pub const ID_SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const ID_SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const ID_SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");
pub const ID_SHA224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.4");
pub const ID_SHA512_224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.5");
pub const ID_SHA512_256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.6");
// Skipping SHA3 for now. Also not including RIPMED-160, Blake, etc.
// pub const ID_SHA3_224: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.7");
// pub const ID_SHA3_256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.7");

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum DigestAlgorithmIdentifier {
    Sha1(Parameters),
    Sha256(Parameters),
    Sha384(Parameters),
    Sha512(Parameters),
    Sha224(Parameters),
    Sha512_224(Parameters),
    Sha512_256(Parameters),
    Unknown(AnyAlgorithmIdentifier),
}

/// See ICAO-9303-10 4.6 Note 2
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Parameters {
    Absent,
    Null,
}

impl<'a> Sequence<'a> for DigestAlgorithmIdentifier {}

impl DigestAlgorithmIdentifier {
    pub fn oid(&self) -> Oid {
        match self {
            Self::Sha1(_) => ID_SHA1,
            Self::Sha256(_) => ID_SHA256,
            Self::Sha384(_) => ID_SHA384,
            Self::Sha512(_) => ID_SHA512,
            Self::Sha224(_) => ID_SHA224,
            Self::Sha512_224(_) => ID_SHA512_224,
            Self::Sha512_256(_) => ID_SHA512_256,
            Self::Unknown(AnyAlgorithmIdentifier { algorithm, .. }) => *algorithm,
        }
    }

    pub fn parameters(&self) -> Option<Any> {
        let params = match self {
            Self::Sha1(params) => *params,
            Self::Sha256(params) => *params,
            Self::Sha384(params) => *params,
            Self::Sha512(params) => *params,
            Self::Sha224(params) => *params,
            Self::Sha512_224(params) => *params,
            Self::Sha512_256(params) => *params,
            Self::Unknown(AnyAlgorithmIdentifier { parameters, .. }) => return parameters.clone(),
        };
        match params {
            Parameters::Absent => None,
            Parameters::Null => Some(Null.into()),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1(_) => "SHA1",
            Self::Sha256(_) => "SHA2-256",
            Self::Sha384(_) => "SHA2-384",
            Self::Sha512(_) => "SHA2-512",
            Self::Sha224(_) => "SHA2-224",
            Self::Sha512_224(_) => "SHA2-512-224",
            Self::Sha512_256(_) => "SHA2-512-256",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn hash_bytes(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1(_) => hash::<sha1::Sha1>(data),
            Self::Sha256(_) => hash::<sha2::Sha256>(data),
            Self::Sha384(_) => hash::<sha2::Sha384>(data),
            Self::Sha512(_) => hash::<sha2::Sha512>(data),
            Self::Sha224(_) => hash::<sha2::Sha224>(data),
            Self::Sha512_224(_) => hash::<sha2::Sha512_224>(data),
            Self::Sha512_256(_) => hash::<sha2::Sha512_256>(data),
            Self::Unknown(algo) => panic!("Unknown algorithm: {:?}", algo),
        }
    }

    pub fn hash_der<T: Encode>(&self, object: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        object.encode_to_vec(&mut bytes).unwrap();
        self.hash_bytes(&bytes)
    }
}

impl Display for DigestAlgorithmIdentifier {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let name = match self {
            Self::Sha1(_) => "SHA1",
            Self::Sha256(_) => "SHA2-256",
            Self::Sha384(_) => "SHA2-384",
            Self::Sha512(_) => "SHA2-512",
            Self::Sha224(_) => "SHA2-224",
            Self::Sha512_224(_) => "SHA2-512-224",
            Self::Sha512_256(_) => "SHA2-512-256",
            Self::Unknown(_) => "UNKNOWN",
        };
        write!(f, "{name}")
    }
}

impl TryFrom<&str> for DigestAlgorithmIdentifier {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1(Parameters::Absent)),
            "SHA2-256" => Ok(Self::Sha256(Parameters::Absent)),
            "SHA2-384" => Ok(Self::Sha384(Parameters::Absent)),
            "SHA2-512" => Ok(Self::Sha512(Parameters::Absent)),
            "SHA2-224" => Ok(Self::Sha224(Parameters::Absent)),
            "SHA2-512-224" => Ok(Self::Sha512_224(Parameters::Absent)),
            "SHA2-512-256" => Ok(Self::Sha512_256(Parameters::Absent)),
            _ => Err(Error::new(
                ErrorKind::Value { tag: Tag::Null },
                Length::ZERO,
            )),
        }
    }
}

fn hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hash.to_vec()
}

impl From<&DigestAlgorithmIdentifier> for AnyAlgorithmIdentifier {
    fn from(digest: &DigestAlgorithmIdentifier) -> Self {
        AnyAlgorithmIdentifier {
            algorithm:  digest.oid(),
            parameters: digest.parameters(),
        }
    }
}

impl TryFrom<AnyAlgorithmIdentifier> for DigestAlgorithmIdentifier {
    type Error = Error;

    fn try_from(algo: AnyAlgorithmIdentifier) -> Result<Self> {
        let params = match &algo.parameters {
            None => Ok(Parameters::Absent),
            Some(any) if any.is_null() => Ok(Parameters::Null),
            Some(any) => Err(Error::new(
                ErrorKind::TagUnexpected {
                    expected: Some(Tag::Null),
                    actual:   any.tag(),
                },
                Length::ZERO,
            )),
        };
        Ok(match algo.algorithm {
            ID_SHA1 => Self::Sha1(params?),
            ID_SHA256 => Self::Sha256(params?),
            ID_SHA384 => Self::Sha384(params?),
            ID_SHA512 => Self::Sha512(params?),
            ID_SHA224 => Self::Sha224(params?),
            ID_SHA512_224 => Self::Sha512_224(params?),
            ID_SHA512_256 => Self::Sha512_256(params?),
            _ => Self::Unknown(algo),
        })
    }
}

impl EncodeValue for DigestAlgorithmIdentifier {
    fn value_len(&self) -> Result<Length> {
        AnyAlgorithmIdentifier::from(self).value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> Result<()> {
        AnyAlgorithmIdentifier::from(self).encode_value(encoder)
    }
}

impl<'a> DecodeValue<'a> for DigestAlgorithmIdentifier {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: der::Header) -> Result<Self> {
        let any = AnyAlgorithmIdentifier::decode_value(reader, header)?;
        DigestAlgorithmIdentifier::try_from(any)
            .map_err(|err| Error::new(err.kind(), reader.position()))
    }
}
