//! A compile-time typed version of `ContentInfo`
//!
//! See [`cms::content_info::ContentInfo`] for a dynamic version.

use {
    cms::signed_data::SignedData,
    der::{
        asn1::{ContextSpecific, ContextSpecificRef, ObjectIdentifier as Oid},
        Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Header, Length, Reader, Result,
        Sequence, Tag, TagMode, TagNumber, Tagged, Writer,
    },
};

pub trait ContentType: Encode + EncodeValue + Tagged + for<'a> Decode<'a> {
    const CONTENT_TYPE: Oid;
}

/// The `ContentInfo` type is defined in [RFC 5652 Section 3].
///
/// ```text
///   ContentInfo ::= SEQUENCE {
///       contentType        CONTENT-TYPE.
///                       &id({ContentSet}),
///       content            [0] EXPLICIT CONTENT-TYPE.
///                       &Type({ContentSet}{@contentType})}
/// ```
///
/// In this implementation `contentType` is provided compile time through the
/// [`ContentType`] trait and `content` is provided as `.0` of the `ContentInfo`
/// struct.
///
/// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentInfo<T: ContentType>(pub T);

impl ContentType for SignedData {
    const CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
}

impl<T: ContentType> Sequence<'_> for ContentInfo<T> {}

impl<T: ContentType> EncodeValue for ContentInfo<T> {
    fn value_len(&self) -> Result<Length> {
        let content_type_len = T::CONTENT_TYPE.encoded_len()?;
        let content_len = ContextSpecificRef {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: &self.0,
        }
        .encoded_len()?;
        content_type_len + content_len
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        T::CONTENT_TYPE.encode(writer)?;
        ContextSpecificRef {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: &self.0,
        }
        .encode(writer)
    }
}

impl<'a, T: ContentType> DecodeValue<'a> for ContentInfo<T> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        reader.read_nested(header.length, |reader| {
            // Read and check the content type
            let content_type = reader.decode()?;
            if content_type != T::CONTENT_TYPE {
                return Err(Error::new(
                    ErrorKind::OidUnknown { oid: content_type },
                    reader.position(),
                ));
            }

            // Read the content
            let content = match ContextSpecific::decode(reader)? {
                field if field.tag_number == TagNumber::N0 => Some(field),
                _ => None,
            }
            .ok_or_else(|| {
                Tag::ContextSpecific {
                    number: TagNumber::N0,
                    constructed: false,
                }
                .value_error()
            })?
            .value;

            Ok(Self(content))
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        der::{asn1::ObjectIdentifier, Decode},
        hex_literal::hex,
    };

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct TestObject {
        pub a: u8,
        pub b: u8,
    }

    impl ContentType for TestObject {
        const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
    }

    #[test]
    fn test_encode_decode() {
        let content_info = ContentInfo(TestObject { a: 1, b: 2 });
        let expected = hex!("30 14 06082b06010505073001a0083006020101020102");

        let mut encoded = vec![];
        content_info.encode_to_vec(&mut encoded).unwrap();
        dbg!(hex::encode(&encoded));
        assert_eq!(encoded, expected);

        let decoded = ContentInfo::<TestObject>::from_der(&encoded).unwrap();
        assert_eq!(decoded, content_info);
    }
}
