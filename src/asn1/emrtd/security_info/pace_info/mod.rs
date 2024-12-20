mod pace_protocol;

pub use pace_protocol::PaceProtocol;
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
    pub parameter_id: Option<u64>,
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
