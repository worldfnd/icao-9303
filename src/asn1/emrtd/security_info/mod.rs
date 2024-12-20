mod chip_authentication_info;
mod pace_info;

pub use {
    self::pace_info::{PaceInfo, PaceProtocol},
    chip_authentication_info::{
        ChipAuthenticationInfo, ChipAuthenticationProtocol, ChipAuthenticationPublicKeyInfo,
    },
};
use {
    super::ordered_set::OrderedSet,
    crate::ensure_err,
    der::{
        asn1::{ObjectIdentifier as Oid, OctetString},
        Any, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, FixedTag, Header, Length,
        Reader, Result, Sequence, Tag, ValueOrd, Writer,
    },
    pace_info::PaceDomainParameterInfo,
    serde::{Deserialize, Serialize},
    std::{
        cmp::Ordering,
        fmt::{self, Display, Formatter},
    },
};

pub const KEY_AGREEMENT_OID: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.1");
pub const ID_ACTIVE_AUTHENTICATION: Oid = Oid::new_unwrap("2.23.136.1.1.5");
pub const ID_TERMINAL_AUTHENTICATION: Oid = Oid::new_unwrap("0.4.0.127.0.7.2.2.2");
pub const ID_EF_DIR: Oid = Oid::new_unwrap("2.23.136.1.1.13");

/// A [`SecurityInfos`] object from ICAO-9303-11 9.2.
///
/// ```asn1
/// SecurityInfos ::= SET OF SecurityInfo
/// ```
pub type SecurityInfos = OrderedSet<SecurityInfo>;

/// Various subtypes of `SecurityInfo` from ICAO-9303-11 9.2.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SecurityInfo {
    Pace(PaceInfo),
    PaceDomainParameter(PaceDomainParameterInfo),
    ChipAuthentication(ChipAuthenticationInfo),
    ChipAuthenticationPublicKey(ChipAuthenticationPublicKeyInfo),
    ActiveAutentication(ActiveAuthenticationInfo),
    TerminalAuthentication(TerminalAuthenticationInfo),
    EfDir(EfDirInfo),
    Unknow(AnySecurityInfo),
}

/// A [`SecurityInfo`] object from ICAO-9303-11 9.2.
///
/// ```asn1
/// SecurityInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER,
///     requiredData ANY DEFINED BY protocol,
///     optionalData ANY DEFINED BY protocol OPTIONAL
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Sequence, ValueOrd)]
pub struct AnySecurityInfo {
    pub protocol: Oid,
    pub required_data: Any,
    pub optional_data: Option<Any>,
}

#[derive(Clone, PartialEq, Eq, Debug, Sequence, ValueOrd)]
pub struct EfDirInfo {
    pub protocol: Oid,
    pub ef_dir: OctetString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyAgreement {
    /// Diffie-Hellman over a prime field.
    Dh,

    /// Elliptic Curve Diffie-Hellman.
    Ecdh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SymmetricCipher {
    Tdes,
    Aes128,
    Aes192,
    Aes256,
}

pub type ActiveAuthenticationInfo = AnySecurityInfo; // TODO
pub type TerminalAuthenticationInfo = AnySecurityInfo; // TODO

impl SecurityInfo {
    pub fn protocol(&self) -> Oid {
        match self {
            Self::Pace(info) => Oid::from(info.protocol),
            Self::PaceDomainParameter(info) => info.protocol.into(),
            Self::ChipAuthentication(info) => info.protocol.into(),
            Self::ChipAuthenticationPublicKey(info) => info.protocol.into(),
            Self::ActiveAutentication(info) => info.protocol,
            Self::TerminalAuthentication(info) => info.protocol,
            Self::EfDir(info) => info.protocol,
            Self::Unknow(info) => info.protocol,
        }
    }

    pub fn protocol_name(&self) -> String {
        match self {
            Self::Pace(info) => info.protocol.to_string(),
            Self::PaceDomainParameter(info) => info.protocol.to_string(),
            Self::ChipAuthentication(info) => info.protocol.to_string(),
            Self::ChipAuthenticationPublicKey(info) => info.to_string(),
            Self::ActiveAutentication(_info) => "AA".to_string(),
            Self::TerminalAuthentication(_info) => "TA".to_string(),
            Self::EfDir(_info) => "EF_DIR".to_string(),
            Self::Unknow(info) => info.protocol.to_string(),
        }
    }
}

impl Sequence<'_> for SecurityInfo {}

impl ValueOrd for SecurityInfo {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        let self_der = self.to_der()?;
        let other_der = other.to_der()?;
        let self_any = AnySecurityInfo::from_der(&self_der)?;
        let other_any = AnySecurityInfo::from_der(&other_der)?;
        self_any.value_cmp(&other_any)
    }
}

impl EncodeValue for SecurityInfo {
    fn value_len(&self) -> Result<Length> {
        match self {
            Self::Pace(info) => info.value_len(),
            Self::PaceDomainParameter(info) => info.value_len(),
            Self::ChipAuthentication(info) => info.value_len(),
            Self::ChipAuthenticationPublicKey(info) => info.value_len(),
            Self::ActiveAutentication(info) => info.value_len(),
            Self::TerminalAuthentication(info) => info.value_len(),
            Self::EfDir(info) => info.value_len(),
            Self::Unknow(info) => info.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            Self::Pace(info) => info.encode_value(writer),
            Self::PaceDomainParameter(info) => info.encode_value(writer),
            Self::ChipAuthentication(info) => info.encode_value(writer),
            Self::ChipAuthenticationPublicKey(info) => info.encode_value(writer),
            Self::ActiveAutentication(info) => info.encode_value(writer),
            Self::TerminalAuthentication(info) => info.encode_value(writer),
            Self::EfDir(info) => info.encode_value(writer),
            Self::Unknow(info) => info.encode_value(writer),
        }
    }
}

impl<'a> DecodeValue<'a> for SecurityInfo {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let offset = reader.position();
        let offset_err = |err: Error| {
            Error::new(
                err.kind(),
                err.position()
                    .map_or(offset, |p| (p + offset).unwrap_or(offset)),
            )
        };
        let any = AnySecurityInfo::decode_value(reader, header)?;
        let der = any.to_der()?;
        if let Ok(protocol) = PaceProtocol::try_from(any.protocol) {
            if protocol.cipher.is_some() {
                PaceInfo::from_der(&der).map_err(offset_err).map(Self::Pace)
            } else {
                PaceDomainParameterInfo::from_der(&der)
                    .map_err(offset_err)
                    .map(Self::PaceDomainParameter)
            }
        } else if ChipAuthenticationProtocol::try_from(any.protocol).is_ok() {
            ChipAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ChipAuthentication)
        } else if KeyAgreement::try_from(any.protocol).is_ok() {
            ChipAuthenticationPublicKeyInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ChipAuthenticationPublicKey)
        } else if any.protocol == ID_ACTIVE_AUTHENTICATION {
            ActiveAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::ActiveAutentication)
        } else if any.protocol == ID_TERMINAL_AUTHENTICATION {
            // TODO: This ID can be a prefix.
            TerminalAuthenticationInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::TerminalAuthentication)
        } else if any.protocol == ID_EF_DIR {
            EfDirInfo::from_der(&der)
                .map_err(offset_err)
                .map(Self::EfDir)
        } else {
            Ok(Self::Unknow(any))
        }
    }
}

impl Display for KeyAgreement {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Dh => write!(f, "DH"),
            Self::Ecdh => write!(f, "ECDH"),
        }
    }
}

impl TryFrom<Oid> for KeyAgreement {
    type Error = Error;

    fn try_from(oid: Oid) -> Result<Self> {
        let err = Error::new(ErrorKind::OidUnknown { oid }, Length::ZERO);
        ensure_err!(oid.parent() == Some(KEY_AGREEMENT_OID), err);
        match oid.arc(9) {
            Some(1) => Ok(KeyAgreement::Dh),
            Some(2) => Ok(KeyAgreement::Ecdh),
            _ => Err(err),
        }
    }
}

impl From<KeyAgreement> for Oid {
    fn from(ka: KeyAgreement) -> Self {
        KEY_AGREEMENT_OID
            .push_arc(match ka {
                KeyAgreement::Dh => 1,
                KeyAgreement::Ecdh => 2,
            })
            .unwrap()
    }
}

impl FixedTag for KeyAgreement {
    const TAG: Tag = Oid::TAG;
}

impl EncodeValue for KeyAgreement {
    fn value_len(&self) -> Result<Length> {
        Oid::from(*self).value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        Oid::from(*self).encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for KeyAgreement {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Oid::decode_value(reader, header).and_then(|oid| {
            Self::try_from(oid).map_err(|err| Error::new(err.kind(), reader.position()))
        })
    }
}

impl Display for SymmetricCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tdes => write!(f, "3DES-CBC-CBC"),
            Self::Aes128 => write!(f, "AES-CBC-CMAC-128"),
            Self::Aes192 => write!(f, "AES-CBC-CMAC-192"),
            Self::Aes256 => write!(f, "AES-CBC-CMAC-256"),
        }
    }
}
