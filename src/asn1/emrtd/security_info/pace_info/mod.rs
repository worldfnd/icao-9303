mod pace_protocol;

pub use pace_protocol::{KeyMapping as PaceKeyMapping, PaceProtocol};
use {crate::asn1::AnyAlgorithmIdentifier, der::Sequence};

/// See ICAO-9303-11 9.2.1
#[derive(Clone, PartialEq, Eq, Debug, Sequence)]
pub struct PaceInfo {
    pub protocol: PaceProtocol,

    /// Version must be 2
    pub version: u64,

    pub parameter_id: Option<u64>,
}

/// See ICAO-9303-11 9.2.2
#[derive(Clone, PartialEq, Eq, Debug, Sequence)]
pub struct PaceDomainParameterInfo {
    pub protocol: PaceProtocol,

    /// Algorithm identifier for the domain parameter.
    pub domain_parameter: AnyAlgorithmIdentifier,
    pub parameter_id:     Option<u64>,
}

impl PaceInfo {
    pub fn ensure_valid(&self) {
        assert!(self.protocol.cipher.is_some());
        assert_eq!(self.version, 2);
    }
}

impl PaceDomainParameterInfo {
    pub fn ensure_valid(&self) {
        assert!(self.protocol.cipher.is_none());
    }
}

/// Standardized Domain Parameters
///
/// See ICAO 9303-11 9.5.1
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardizedDomainParameter {
    // See RFC 5114: Additional Diffie-Hellman Groups for Use with IETF Standards
    Modp1024_160      = 0, // RFC 5114-2.2
    Modp2048_224      = 1, // RFC 5114-2.3
    Modp2048_256      = 2, // RFC 5114-2.4
    // See RFC 5639:Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve
    // Generation
    EcSecp192r1       = 8, // NIST P-192, SECG p192r1, FIPS 186-4
    EcBrainpoolp192r1 = 9,
    EcSecp224r1       = 10,
    EcBrainpoolp224r1 = 11,
    EcSecp256r1       = 12,
    EcBrainpoolp256r1 = 13,
    EcBrainpoolp320r1 = 14,
    EcSecp384r1       = 15,
    EcBrainpoolp384r1 = 16,
    EcBrainpoolp512r1 = 17,
    EcSecp521r1       = 18,
    // 3-7 and 19-31.
    ReservedForFutureUse(u64),
}

impl From<u64> for StandardizedDomainParameter {
    fn from(val: u64) -> StandardizedDomainParameter {
        match val {
            0 => Self::Modp1024_160,
            1 => Self::Modp2048_224,
            2 => Self::Modp2048_256,
            8 => Self::EcSecp192r1,
            9 => Self::EcBrainpoolp192r1,
            10 => Self::EcSecp224r1,
            11 => Self::EcBrainpoolp224r1,
            12 => Self::EcSecp256r1,
            13 => Self::EcBrainpoolp256r1,
            14 => Self::EcBrainpoolp320r1,
            15 => Self::EcSecp384r1,
            16 => Self::EcBrainpoolp384r1,
            17 => Self::EcBrainpoolp512r1,
            18 => Self::EcSecp521r1,
            _ => Self::ReservedForFutureUse(val),
        }
    }
}
