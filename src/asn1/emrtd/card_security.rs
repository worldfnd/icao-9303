use {
    super::{security_info::SecurityInfos, ContentInfo, ContentType},
    crate::ensure_err,
    cms::signed_data::{EncapsulatedContentInfo, SignedData},
    der::{
        self,
        asn1::{ObjectIdentifier as Oid, OctetString},
        Decode, Encode, Error, ErrorKind, Length, Reader, Result, Writer,
    },
};

/// EF.CardSecurity is a ContentInfo-wrapped [`SignedData`] structure.
///
/// See ICAO 9303-10 3.11.4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfCardSecurity(ContentInfo<SignedData>);

impl Encode for EfCardSecurity {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for EfCardSecurity {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        Ok(Self(ContentInfo::<SignedData>::decode(reader)?))
    }
}

impl ContentType for SecurityInfos {
    /// BSI TR-03110, BSI Security Object
    const CONTENT_TYPE: Oid = Oid::new_unwrap("0.4.0.127.0.7.3.2.1");
}

impl EfCardSecurity {
    pub fn signed_data(&self) -> &SignedData {
        &self.0 .0
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.signed_data().encap_content_info
    }

    pub fn security_infos(&self) -> Result<SecurityInfos> {
        let econ = self.encapsulated_content();
        ensure_err!(
            econ.econtent_type == SecurityInfos::CONTENT_TYPE,
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
                    expected: Some(der::Tag::OctetString),
                    actual:   der::Tag::Null, // Actually None
                },
                Length::ZERO,
            ))?
            .decode_as::<OctetString>()?;
        SecurityInfos::from_der(octet_string.as_bytes())
    }
}
