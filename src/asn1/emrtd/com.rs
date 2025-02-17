use der::{
    self,
    asn1::{OctetStringRef, PrintableString},
    Decode, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag, Header, Length, Reader, Tag,
    TagNumber, Writer,
};

/// EF_COM is an [`ApplicationLevelInformation`] structure.
///
/// See ICAO-9303-10 4.6.1.
pub type EfCom = ApplicationLevelInformation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationLevelInformation {
    lds_version:     PrintableString,
    unicode_version: PrintableString,
    dg_tags_present: Vec<Tag>,
}

impl ApplicationLevelInformation {
    pub fn lds_version(&self) -> &PrintableString {
        &self.lds_version
    }

    pub fn unicode_version(&self) -> &PrintableString {
        &self.unicode_version
    }

    pub fn dgs_tags_present(&self) -> &[Tag] {
        &self.dg_tags_present
    }
}

impl FixedTag for ApplicationLevelInformation {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number:      TagNumber::new(0), // 0x60
    };
}

impl EncodeValue for ApplicationLevelInformation {
    fn value_len(&self) -> der::Result<Length> {
        todo!("Application Level Information encoding not supported yet");
    }

    fn encode_value(&self, _encoder: &mut impl Writer) -> der::Result<()> {
        todo!("Application Level Information encoding not supported yet");
    }
}

fn decode_large_tag<'a, R: Reader<'a>, T: DecodeValue<'a>>(
    tag: &[u8],
    reader: &mut R,
) -> der::Result<T> {
    let read_tag = reader.read_slice(Length::new(tag.len().try_into()?))?;
    if read_tag != tag {
        return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
    };
    let len = Length::decode(reader)?;
    let header = Header {
        length: len,
        tag:    Tag::Null, // doesn't matter
    };
    T::decode_value(reader, header)
}

// The `der` crate currently only supports single-octet tags, so we parse some
// stuff manually.
impl<'a> DecodeValue<'a> for ApplicationLevelInformation {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let lds_version = decode_large_tag(&[0x5f, 0x01], reader)?;
        let unicode_version = decode_large_tag(&[0x5f, 0x36], reader)?;

        let dg_tags_present = {
            let tag_5c = reader.read_byte()?;
            if tag_5c != 0x5c {
                return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
            };
            let len = Length::decode(reader)?;
            OctetStringRef::decode_value(reader, der::Header {
                tag:    der::Tag::Null,
                length: len,
            })?
            .as_bytes()
            .iter()
            .map(|&byte| Tag::try_from(byte))
            .collect::<der::Result<Vec<_>>>()?
        };

        Ok(Self {
            lds_version,
            unicode_version,
            dg_tags_present,
        })
    }
}
