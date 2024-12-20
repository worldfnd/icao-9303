use der::{
    self, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Result, Tag,
    TagNumber, Writer,
};

/// Wrapper that adds an application specific tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationTagged<const APPLICATION: u8, T>(pub T);

impl<const APPLICATION: u8, T: for<'a> DecodeValue<'a>> FixedTag
    for ApplicationTagged<APPLICATION, T>
{
    const TAG: Tag = Tag::Application {
        constructed: true,
        number:      TagNumber::new(APPLICATION),
    };
}

impl<const APPLICATION: u8, T: Encode> EncodeValue for ApplicationTagged<APPLICATION, T> {
    fn value_len(&self) -> Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a, const APPLICATION: u8, T: Decode<'a>> DecodeValue<'a>
    for ApplicationTagged<APPLICATION, T>
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> Result<Self> {
        Ok(Self(T::decode(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        der::{asn1::ObjectIdentifier, Decode},
        hex_literal::hex,
    };

    #[test]
    fn test_encode_decode() {
        let app_data =
            ApplicationTagged::<23, _>(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1"));
        let mut buffer = vec![];
        app_data.encode(&mut buffer).unwrap();
        assert_eq!(buffer, hex!("77 0a 06082b06010505073001"));
        let decoded = ApplicationTagged::<23, _>::from_der(&buffer).unwrap();
        assert_eq!(decoded, app_data);
    }
}
