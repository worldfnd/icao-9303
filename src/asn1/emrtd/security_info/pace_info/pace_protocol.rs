use {
    super::super::{KeyAgreement, SymmetricCipher},
    crate::ensure_err,
    der::{
        asn1::ObjectIdentifier as Oid, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag,
        Header, Length, Reader, Result, Tag, Writer,
    },
    std::fmt::{self, Display, Formatter},
};

pub const PACE_OID: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.4");

/// A PACE object identifier.
///
/// See ICAO 9303-11 9.2.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PaceProtocol {
    pub key_agreement: KeyAgreement,
    pub key_mapping: KeyMapping,
    pub cipher: Option<SymmetricCipher>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyMapping {
    /// Generic Mapping
    Gm,

    /// Integrated Mapping
    Im,

    /// Ciphertext Authentication Mapping
    Cam,
}

impl Display for PaceProtocol {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PACE-{}-{}", self.key_agreement, self.key_mapping)?;
        if let Some(cipher) = self.cipher {
            write!(f, "-{cipher}")?;
        }
        Ok(())
    }
}

impl TryFrom<Oid> for PaceProtocol {
    type Error = Error;

    fn try_from(oid: Oid) -> Result<Self> {
        let err = Error::new(ErrorKind::OidUnknown { oid }, Length::ZERO);
        ensure_err!((10..=11).contains(&oid.len()), err);
        let pace_oid = match oid.len() {
            10 => oid.parent().unwrap(),
            11 => oid.parent().unwrap().parent().unwrap(),
            _ => return Err(err),
        };
        ensure_err!(pace_oid == PACE_OID, err);
        let (key_agreement, key_mapping) = match oid.arc(9).unwrap() {
            1 => (KeyAgreement::Dh, KeyMapping::Gm),
            2 => (KeyAgreement::Ecdh, KeyMapping::Gm),
            3 => (KeyAgreement::Dh, KeyMapping::Im),
            4 => (KeyAgreement::Ecdh, KeyMapping::Im),
            // DH CAM not allowed, but 5 reserved
            6 => (KeyAgreement::Ecdh, KeyMapping::Cam),
            _ => return Err(err),
        };
        let cipher: Option<SymmetricCipher> = match oid.arc(10) {
            None => None,
            Some(1) => {
                // 3DES is not allowed in CAM.
                ensure_err!(key_mapping != KeyMapping::Cam, err);
                Some(SymmetricCipher::Tdes)
            }
            Some(2) => Some(SymmetricCipher::Aes128),
            Some(3) => Some(SymmetricCipher::Aes192),
            Some(4) => Some(SymmetricCipher::Aes256),
            _ => return Err(err),
        };
        Ok(Self {
            key_agreement,
            key_mapping,
            cipher,
        })
    }
}

impl From<PaceProtocol> for Oid {
    fn from(pace: PaceProtocol) -> Self {
        let oid = PACE_OID
            .push_arc(match (pace.key_agreement, pace.key_mapping) {
                (KeyAgreement::Dh, KeyMapping::Gm) => 1,
                (KeyAgreement::Ecdh, KeyMapping::Gm) => 2,
                (KeyAgreement::Dh, KeyMapping::Im) => 3,
                (KeyAgreement::Ecdh, KeyMapping::Im) => 4,
                (KeyAgreement::Ecdh, KeyMapping::Cam) => 6,
                _ => panic!("Invalid PACE protocol"),
            })
            .unwrap();
        if let Some(cipher) = pace.cipher {
            oid.push_arc(match cipher {
                SymmetricCipher::Tdes => 1,
                SymmetricCipher::Aes128 => 2,
                SymmetricCipher::Aes192 => 3,
                SymmetricCipher::Aes256 => 4,
            })
            .unwrap()
        } else {
            oid
        }
    }
}

impl FixedTag for PaceProtocol {
    const TAG: Tag = Oid::TAG;
}

impl EncodeValue for PaceProtocol {
    fn value_len(&self) -> der::Result<Length> {
        Oid::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        Oid::from(*self).encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for PaceProtocol {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Oid::decode_value(reader, header).and_then(|oid| {
            Self::try_from(oid).map_err(|err| Error::new(err.kind(), reader.position()))
        })
    }
}

impl Display for KeyMapping {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Gm => write!(f, "GM"),
            Self::Im => write!(f, "IM"),
            Self::Cam => write!(f, "CAM"),
        }
    }
}
