use {
    der::{
        Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Result, Tag,
        Writer,
    },
    std::slice,
};

/// Variant of ASN1 SET that does not respect the cannonical order of the
/// elements.
///
/// Some passports do not order the elements of SET correctly, and we need to
/// preserve this to be able to encode the data back to the exact same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedSet<T>(pub Vec<T>);

impl<T> OrderedSet<T> {
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T> AsRef<[T]> for OrderedSet<T> {
    fn as_ref(&self) -> &[T] {
        self.0.as_slice()
    }
}

impl<T> FixedTag for OrderedSet<T> {
    const TAG: Tag = Tag::Set;
}

impl<T: Encode> EncodeValue for OrderedSet<T> {
    fn value_len(&self) -> Result<Length> {
        self.0
            .iter()
            .fold(Ok(Length::ZERO), |len, elem| len + elem.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        for elem in self.0.iter() {
            elem.encode(writer)?;
        }
        Ok(())
    }
}

impl<'a, T: Decode<'a>> DecodeValue<'a> for OrderedSet<T> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        reader.read_nested(header.length, |reader| {
            let mut inner = Vec::new();
            while !reader.is_finished() {
                inner.push(T::decode(reader)?);
            }
            Ok(Self(inner))
        })
    }
}
