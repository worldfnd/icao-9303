/// ! Common data for DG2, DG3, and DG4.
use der::{
    self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Length,
    Reader, Sequence, Writer,
};

/// Biometric Information Template Group
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiometricInformationGroup<S: BiometricSubtyped>(Vec<BiometricInformation<S>>);

/// Codec helper for Data Groups which employ Biometric Information Template
/// Groups
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BiometricInformationGroupTagged<const TAG: u8, S: BiometricSubtyped>(
    BiometricInformationGroup<S>,
);

/// Biometric Information Template
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiometricInformation<S: BiometricSubtyped> {
    pub header: BiometricHeader<S>,
    pub data:   BiometricData,
}

/// Trait for Biometric sub-types
pub trait BiometricSubtyped: EncodeValue + for<'a> DecodeValue<'a> + der::FixedTag {}

/// Biometric Header Template (BHT)
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct BiometricHeader<S: BiometricSubtyped = BiometricSubtype> {
    /// ICAO header version. CBEFF patron header format (0101)
    #[asn1(context_specific = "0", optional = "true")]
    pub version:       Option<OctetString>, // '02' length
    /// Biometric type
    #[asn1(context_specific = "1", optional = "true")]
    pub btype:         Option<OctetString>, // '01-03' length
    /// Biometric sub-type
    pub bsubtype:      S, // '01' length
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
pub struct BiometricData {
    pub encoding: BiometricDataEncoding,
    pub bytes:    Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricDataEncoding {
    Iso19794,
    // TODO ISO 39794 can be further DER-decoded
    Iso39794,
}

/// Generic Biometric sub-type used in the [`BiometricHeader`].
/// Is an optional OCTET STRING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricSubtype(Option<OctetString>);

/// Used to identify the side of a hand (DG3) or iris (DG4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    NoInformation = 0b00,
    Right         = 0b01,
    Left          = 0b10,
}

impl BiometricSubtype {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|os| os.as_bytes())
    }
}

impl der::FixedTag for BiometricSubtype {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: false,
        number:      der::TagNumber::new(2),
    };
}
impl BiometricSubtyped for BiometricSubtype {}

impl EncodeValue for BiometricSubtype {
    fn value_len(&self) -> der::Result<Length> {
        if let Some(os) = &self.0 {
            os.value_len()
        } else {
            Ok(Length::new(0))
        }
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        if let Some(os) = &self.0 {
            os.encode_value(encoder)?;
        }
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for BiometricSubtype {
    fn decode_value<R: Reader<'a>>(reader: &mut R, h: der::Header) -> der::Result<Self> {
        let bytes = reader.read_slice(h.length)?;
        Ok(Self(Some(OctetString::new(bytes)?)))
    }
}

impl<S: BiometricSubtyped> Encode for BiometricInformationGroup<S> {
    fn encoded_len(&self) -> der::Result<Length> {
        todo!("Biometric Information Group encoding not supported yet");
    }

    fn encode(&self, _encoder: &mut impl Writer) -> der::Result<()> {
        todo!("Biometric Information Group encoding not supported yet");
    }
}

// The `der` crate currently only supports single-octet tags, so we parse some
// stuff manually.
impl<'a, S: BiometricSubtyped> Decode<'a> for BiometricInformationGroup<S> {
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
                    tag:    der::Tag::Null, // 0xa1
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
                    bytes: reader.read_vec(len)?,
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
                tag:    der::Tag::Null, // 0x53
                length: len,
            })?;
        }

        Ok(Self(insts))
    }
}

impl<const TAG: u8, S: BiometricSubtyped> BiometricInformationGroupTagged<TAG, S> {
    pub fn infos(&self) -> &[BiometricInformation<S>] {
        &self.0 .0
    }
}

impl<const TAG: u8, S: BiometricSubtyped> Encode for BiometricInformationGroupTagged<TAG, S> {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a, const TAG: u8, S: BiometricSubtyped> Decode<'a>
    for BiometricInformationGroupTagged<TAG, S>
{
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag_byte = reader.read_byte()?;
        if tag_byte != TAG {
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
