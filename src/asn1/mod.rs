//! Pure ASN1 types, no application logic.
//!
//! Parsing is done as deeply, for example a `SecurityInfo` is parsed into an
//! enum of the known OIDs with a catch-all for unimplemented cases. This
//! ensures that rich types are available for the application to use, but still
//! allows for parsing of all valid inputs.
//!
//! A second goal is for the parsing to be exactly reversible. In this is
//! guaranteed by DER, but unfortunately real world data is not always DER
//! compliant, or the standard is ambiguous. In this case we take care to store
//! the details of the input, so that the output can be exactly reconstructed.
//! See for example the [`DigestAlgorithmIdentifier`] parameters (which have two
//! wayss of encoding 'no parameters') and [`OrderedSet`].

mod application_tagged;
mod content_info;
mod digest_algorithm_identifier;
pub mod emrtd;
mod ordered_set;
pub mod public_key_info;
mod signature_algorithm_identifier;

pub use self::{
    application_tagged::ApplicationTagged,
    content_info::{ContentInfo, ContentType},
    digest_algorithm_identifier::{
        DigestAlgorithmIdentifier, Parameters as DigestAlgorithmParameters,
    },
    signature_algorithm_identifier::SignatureAlgorithmIdentifier,
};
use der::{asn1::ObjectIdentifier as Oid, Any, Sequence, ValueOrd};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence, ValueOrd)]
pub struct AnyAlgorithmIdentifier {
    pub algorithm:  Oid,
    pub parameters: Option<Any>,
}
