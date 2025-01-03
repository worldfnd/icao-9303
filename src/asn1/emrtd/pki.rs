use {
    super::{ApplicationTagged, ContentInfo, ContentType, DigestAlgorithmIdentifier},
    crate::ensure_err,
    cms::{
        cert::x509::Certificate,
        signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo},
    },
    der::{
        asn1::{ObjectIdentifier as Oid, OctetString, SetOfVec},
        Decode, Error, ErrorKind, Length, Result, Sequence, Tag,
    },
};

/// Master Lists are implemented as instances of the ContentInfo Type, as
/// specified in [RFC 5652]. The ContentInfo contains a single instance of
/// SignedData.
///
/// See ICAO 9303-12 9
pub type MasterList = ContentInfo<SignedData>;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct CscaMasterList {
    pub version:   u64,
    pub cert_list: SetOfVec<Certificate>,
}

impl ContentType for CscaMasterList {
    /// ICAO 9303-12 9.2
    const CONTENT_TYPE: Oid = Oid::new_unwrap("2.23.136.1.1.2");
}

impl MasterList {
    pub fn signed_data(&self) -> &SignedData {
        &self.0
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.0.encap_content_info
    }

    /// MasterList contains the CSCA Master List as encapsulated content.
    pub fn csca_ml(&self) -> Result<CscaMasterList> {
        let econ = self.encapsulated_content();
        ensure_err!(
            econ.econtent_type == CscaMasterList::CONTENT_TYPE,
            Error::new(
                ErrorKind::OidUnknown {
                    oid: econ.econtent_type,
                },
                Length::ZERO,
            )
        );
        let octet_string = econ
            .econtent
            .as_ref()
            .ok_or(Error::new(
                ErrorKind::TagUnexpected {
                    expected: Some(Tag::OctetString),
                    actual:   Tag::Null, // Actually None
                },
                Length::ZERO,
            ))?
            .decode_as::<OctetString>()?;
        CscaMasterList::from_der(octet_string.as_bytes())
    }
}
