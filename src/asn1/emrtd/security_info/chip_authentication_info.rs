use {
    super::{super::public_key::SubjectPublicKeyInfo, KeyAgreement, SymmetricCipher},
    crate::ensure_err,
    der::{
        asn1::ObjectIdentifier as Oid, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag,
        Header, Length, Reader, Result, Sequence, Tag, Writer,
    },
    std::fmt::{self, Display, Formatter},
};

pub const CHIP_AUTHENTICATION_OID: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.3");

/// See ICAO 9303-11 9.2.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Sequence)]
pub struct ChipAuthenticationInfo {
    pub protocol: ChipAuthenticationProtocol,
    pub version: u64,
    pub key_id: Option<u64>,
}

/// See ICAO 9303-11 9.2.6.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Sequence)]
pub struct ChipAuthenticationPublicKeyInfo {
    pub protocol: KeyAgreement,
    pub public_key: SubjectPublicKeyInfo,
    pub key_id: Option<u64>,
}

/// See ICAO 9303-11 9.2.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChipAuthenticationProtocol {
    pub key_agreement: KeyAgreement,
    pub cipher: Option<SymmetricCipher>,
}

impl ChipAuthenticationInfo {
    pub fn ensure_valid(self) {
        assert!(self.protocol.cipher.is_some());
        assert_eq!(self.version, 1);
    }
}

impl Display for ChipAuthenticationProtocol {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "CA-{}", self.key_agreement)?;
        if let Some(cipher) = self.cipher {
            write!(f, "-{}", cipher)?;
        }
        Ok(())
    }
}

impl Display for ChipAuthenticationPublicKeyInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "CA-PUBKEY-{}-{}",
            self.protocol,
            self.public_key.subject_public_key.bit_len()
        )
    }
}

impl TryFrom<Oid> for ChipAuthenticationProtocol {
    type Error = Error;

    fn try_from(oid: Oid) -> Result<Self> {
        let err = Error::new(ErrorKind::OidUnknown { oid }, Length::ZERO);
        ensure_err!((10..=11).contains(&oid.len()), err);
        let pace_oid = match oid.len() {
            10 => oid.parent().unwrap(),
            11 => oid.parent().unwrap().parent().unwrap(),
            _ => return Err(err),
        };
        ensure_err!(pace_oid == CHIP_AUTHENTICATION_OID, err);
        let key_agreement = match oid.arc(9).unwrap() {
            1 => KeyAgreement::Dh,
            2 => KeyAgreement::Ecdh,
            _ => return Err(err),
        };
        let cipher: Option<SymmetricCipher> = match oid.arc(10) {
            None => None,
            Some(1) => Some(SymmetricCipher::Tdes),
            Some(2) => Some(SymmetricCipher::Aes128),
            Some(3) => Some(SymmetricCipher::Aes192),
            Some(4) => Some(SymmetricCipher::Aes256),
            _ => return Err(err),
        };
        Ok(Self {
            key_agreement,
            cipher,
        })
    }
}

impl From<ChipAuthenticationProtocol> for Oid {
    fn from(ca: ChipAuthenticationProtocol) -> Self {
        let oid = CHIP_AUTHENTICATION_OID
            .push_arc(match ca.key_agreement {
                KeyAgreement::Dh => 1,
                KeyAgreement::Ecdh => 2,
            })
            .unwrap();
        if let Some(cipher) = ca.cipher {
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

impl FixedTag for ChipAuthenticationProtocol {
    const TAG: Tag = Oid::TAG;
}

impl EncodeValue for ChipAuthenticationProtocol {
    fn value_len(&self) -> Result<Length> {
        Oid::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        Oid::from(*self).encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for ChipAuthenticationProtocol {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Oid::decode_value(reader, header).and_then(|oid| {
            Self::try_from(oid).map_err(|err| Error::new(err.kind(), reader.position()))
        })
    }
}
