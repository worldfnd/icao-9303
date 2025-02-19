/// ! Common data for DG2, DG3, and DG4.
use der::{
    self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Length,
    Reader, Sequence, Tag, Writer,
};

/// Biometric Information Template Group
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiometricInformationGroup<T: BiometricType>(Vec<BiometricInformation<T>>);

/// Codec helper for Data Groups which employ Biometric Information Template
/// Groups
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BiometricInformationGroupTagged<T: BiometricType>(BiometricInformationGroup<T>);

/// Biometric Information Template
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiometricInformation<T: BiometricType> {
    pub header: BiometricHeader<T>,
    pub data:   BiometricData<T>,
}

/// A support collection of types for the encoding of each type of Biometric
/// data
pub trait BiometricType {
    const GROUP_TAG: u8;
    type Subtype: EncodeValue
        + for<'a> DecodeValue<'a>
        + der::FixedTag
        + Clone
        + std::fmt::Debug
        + Eq;
    type Data: for<'a> DecodeValue<'a> + der::FixedTag + Clone + std::fmt::Debug + Eq;
}

/// Biometric Header Template (BHT)
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct BiometricHeader<T: BiometricType> {
    /// ICAO header version. CBEFF patron header format (0101)
    #[asn1(context_specific = "0", optional = "true")]
    pub version:       Option<OctetString>, // '02' length
    /// Biometric type
    #[asn1(context_specific = "1", optional = "true")]
    pub btype:         Option<OctetString>, // '01-03' length
    /// Biometric sub-type
    pub bsubtype:      T::Subtype, // '01' length
    /// Creation date and time
    #[asn1(context_specific = "3", optional = "true")]
    pub creation_date: Option<OctetString>, // '07' length
    /// Validity period
    #[asn1(context_specific = "5", optional = "true")]
    pub validity:      Option<OctetString>, // '08' length
    /// Creator of the biometric reference data (PID)
    #[asn1(context_specific = "6", optional = "true")]
    pub creator:       Option<OctetString>, // '04' length
    /// Format owner
    #[asn1(context_specific = "7")]
    pub format_owner:  OctetString, // '02' length
    /// Format type
    #[asn1(context_specific = "8")]
    pub format_type:   OctetString, // '02' length
}

/// Biometric Data Block (BDB)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricData<T: BiometricType> {
    pub encoding: BiometricDataEncoding,
    pub data:     T::Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricDataEncoding {
    Iso19794,
    // TODO ISO 39794 can be further DER-decoded
    Iso39794,
}

/// Used to identify the side of a hand (DG3) or iris (DG4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    NoInformation = 0b00,
    Right         = 0b01,
    Left          = 0b10,
}

impl<T: BiometricType> Encode for BiometricInformationGroup<T> {
    fn encoded_len(&self) -> der::Result<Length> {
        todo!("Biometric Information Group encoding not supported yet");
    }

    fn encode(&self, _encoder: &mut impl Writer) -> der::Result<()> {
        todo!("Biometric Information Group encoding not supported yet");
    }
}

// The `der` crate currently only supports single-octet tags, so we parse some
// stuff manually.
impl<'a, T: BiometricType> Decode<'a> for BiometricInformationGroup<T> {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag_7f61 = reader.read_slice(Length::new(2))?;
        if tag_7f61 != &[0x7f, 0x61] {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        Length::decode(reader)?;

        let no_inst = u8::decode(reader)?; // 1 to 9 encodings
        let mut insts = Vec::with_capacity(no_inst as usize);

        for _ in 0..no_inst {
            let tag_7f60 = reader.read_slice(Length::new(2))?;
            if tag_7f60 != &[0x7f, 0x60] {
                return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
            };
            Length::decode(reader)?;

            let header = {
                let tag_a1 = reader.read_byte()?;
                if tag_a1 != 0xa1 {
                    return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
                };
                let len = Length::decode(reader)?;

                BiometricHeader::decode_value(reader, der::Header {
                    tag:    Tag::Null, // 0xa1
                    length: len,
                })?
            };

            let data = {
                let tag_xf2e = reader.read_slice(Length::new(2))?;
                let encoding = match tag_xf2e {
                    &[0x5f, 0x2e] => BiometricDataEncoding::Iso19794,
                    &[0x7f, 0x2e] => BiometricDataEncoding::Iso39794,
                    _ => return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position())),
                };
                let len = Length::decode(reader)?;
                BiometricData {
                    encoding,
                    data: T::Data::decode_value(reader, der::Header {
                        tag:    Tag::Null,
                        length: len,
                    })?,
                }
            };

            insts.push(BiometricInformation { header, data });
        }

        // Encoding of zero instance, recommended tag 0x53 with random data
        if no_inst == 0 && reader.remaining_len() > 0u8.into() {
            let tag_53 = reader.read_byte()?;
            if tag_53 != 0x53 {
                return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
            };
            let len = Length::decode(reader)?;
            OctetString::decode_value(reader, der::Header {
                tag:    Tag::Null, // 0x53
                length: len,
            })?;
        }

        Ok(Self(insts))
    }
}

impl<T: BiometricType> BiometricInformationGroupTagged<T> {
    pub fn infos(&self) -> &[BiometricInformation<T>] {
        &self.0 .0
    }
}

impl<T: BiometricType> Encode for BiometricInformationGroupTagged<T> {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a, T: BiometricType> Decode<'a> for BiometricInformationGroupTagged<T> {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag_byte = reader.read_byte()?;
        if tag_byte != T::GROUP_TAG {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        Length::decode(reader)?;

        Ok(Self(BiometricInformationGroup::decode(reader)?))
    }
}

impl Side {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Side::Right,
            0b10 => Side::Left,
            _ => Side::NoInformation,
        }
    }
}
