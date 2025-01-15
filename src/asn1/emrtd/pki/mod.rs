mod ldif;
pub mod pkd;

use {
    super::{ContentInfo, ContentType, DigestAlgorithmIdentifier},
    crate::ensure_err,
    cms::{
        cert::{
            x509::{crl::CertificateList, ext::pkix::SubjectKeyIdentifier, Certificate},
            IssuerAndSerialNumber,
        },
        digested_data::Digest,
        signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo},
    },
    der::{
        asn1::{
            Any, GeneralizedTime, Int, ObjectIdentifier as Oid, OctetString, PrintableString,
            SetOfVec,
        },
        Choice, Decode, Encode, EncodeValue, Error, ErrorKind, Length, Reader, Result, Sequence,
        Tag, ValueOrd, Writer,
    },
    std::cmp::Ordering,
};

/// Master Lists are implemented as instances of the ContentInfo Type, as
/// specified in [RFC 5652]. The ContentInfo contains a single instance of
/// SignedData.
///
/// See ICAO 9303-12 9
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterList(pub ContentInfo<SignedData>);

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct CscaMasterList {
    pub version:   u64,
    pub cert_list: SetOfVec<Certificate>,
}

impl ContentType for CscaMasterList {
    /// ICAO 9303-12 9.2
    const CONTENT_TYPE: Oid = Oid::new_unwrap("2.23.136.1.1.2");
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CRL(pub CertificateList);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviationList(pub ContentInfo<SignedData>);

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct ExtendedKeyUsage {
    pub oid: Oid,
}

impl MasterList {
    pub fn signed_data(&self) -> &SignedData {
        &self.0 .0
    }

    /// Returns information of the signer.
    ///
    /// Per ICAO 9303-12, it is recommended that only one SignerInfo is
    /// provided.
    pub fn signer_info(&self) -> Option<&SignerInfo> {
        self.signed_data().signer_infos.0.get(0)
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.0 .0.encap_content_info
    }

    /// MasterList contains the CSCA Master List as encapsulated content.
    pub fn list(&self) -> Result<CscaMasterList> {
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

impl DeviationList {
    pub fn signed_data(&self) -> &SignedData {
        &self.0 .0
    }

    /// Returns information of the signer.
    ///
    /// Per ICAO 9303-12, it is recommended that only one SignerInfo is
    /// provided.
    pub fn signer_info(&self) -> Option<&SignerInfo> {
        self.signed_data().signer_infos.0.get(0)
    }

    pub fn encapsulated_content(&self) -> &EncapsulatedContentInfo {
        &self.0 .0.encap_content_info
    }

    /// DeviationList contains the (Signed) DeviationList as encapsulated
    /// content.
    pub fn list(&self) -> Result<SignedDeviationList> {
        let econ = self.encapsulated_content();
        ensure_err!(
            econ.econtent_type == SignedDeviationList::CONTENT_TYPE,
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
        SignedDeviationList::from_der(octet_string.as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct SignedDeviationList {
    pub version:          u64,
    #[asn1(optional = "true")]
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub deviations:       SetOfVec<Deviation>,
}

impl ContentType for SignedDeviationList {
    /// ICAO 9303-12 10
    const CONTENT_TYPE: Oid = Oid::new_unwrap("2.23.136.1.1.7");
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Deviation {
    pub documents:    DeviationDocuments,
    pub descriptions: SetOfVec<DeviationDescription>,
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence, ValueOrd)]
pub struct DeviationDescription {
    #[asn1(optional = "true")]
    pub description:    PrintableString,
    pub deviation_type: Oid,
    #[asn1(context_specific = "0", optional = "true")]
    pub parameters:     Option<Any>,
    #[asn1(context_specific = "1", optional = "true")]
    pub national_use:   Option<Any>,
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct DeviationDocuments {
    #[asn1(context_specific = "0", optional = "true")]
    pub document_type:    Option<PrintableString>,
    #[asn1(optional = "true")]
    pub dsc_identifier:   Option<DocumentSignerIdentifier>,
    #[asn1(context_specific = "4", optional = "true")]
    pub issuing_date:     Option<IssuancePeriod>,
    #[asn1(context_specific = "5", optional = "true")]
    pub document_numbers: Option<SetOfVec<PrintableString>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum DocumentSignerIdentifier {
    #[asn1(context_specific = "1")]
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "2")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    #[asn1(context_specific = "3")]
    CertificateDigest(Digest),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct IssuancePeriod {
    pub first_issued: GeneralizedTime,
    pub last_issued:  GeneralizedTime,
}

impl ValueOrd for Deviation {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        // TODO: Better method.
        let lhs = self.to_der()?;
        let rhs = other.to_der()?;
        Ok(lhs.as_slice().cmp(rhs.as_slice()))
    }
}

impl<'a> Decode<'a> for MasterList {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        ContentInfo::<SignedData>::decode(reader).map(Self)
    }
}

impl Encode for MasterList {
    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.0.encode(writer)
    }

    fn encoded_len(&self) -> Result<Length> {
        self.0.encoded_len()
    }
}

impl<'a> Decode<'a> for CRL {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        CertificateList::decode(reader).map(Self)
    }
}

impl Encode for CRL {
    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.0.encode(writer)
    }

    fn encoded_len(&self) -> Result<Length> {
        self.0.encoded_len()
    }
}

impl<'a> Decode<'a> for DeviationList {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        ContentInfo::<SignedData>::decode(reader).map(Self)
    }
}

impl Encode for DeviationList {
    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.0.encode(writer)
    }

    fn encoded_len(&self) -> Result<Length> {
        self.0.encoded_len()
    }
}
