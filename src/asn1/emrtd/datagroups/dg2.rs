use der::{
    self, asn1::OctetString, Decode, DecodeValue, Encode, Error, ErrorKind, Length, Reader,
    Sequence, Writer,
};

/// EF.DG1 contains biometric data (face).
///
/// See ICAO-9303-10 4.7.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg2(Vec<BiometricInformation>);

/// Biometric Information Template
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BiometricInformation {
    pub header: BiometricHeader,
    pub data:   BiometricData,
}

/// Biometric Header Template (BHT)
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct BiometricHeader {
    /// ICAO header version. CBEFF patron header format (0101)
    #[asn1(context_specific = "0", optional = "true")]
    pub version:       Option<OctetString>, // '02' length
    /// Biometric type
    #[asn1(context_specific = "1", optional = "true")]
    pub btype:         Option<OctetString>, // '01-03' length
    /// Biometric sub-type
    #[asn1(context_specific = "2", optional = "true")]
    pub bsubtype:      Option<OctetString>, // '01' length
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

impl EfDg2 {
    pub fn infos(&self) -> &[BiometricInformation] {
        &self.0
    }
}

impl Encode for EfDg2 {
    fn encoded_len(&self) -> der::Result<Length> {
        todo!("EF.DG2 encoding not supported yet")
    }

    fn encode(&self, _encoder: &mut impl Writer) -> der::Result<()> {
        todo!("EF.DG2 encoding not supported yet")
    }
}

// The `der` crate currently only supports single-octet tags, so we parse some
// stuff manually.
impl<'a> Decode<'a> for EfDg2 {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag_75 = reader.read_byte()?;
        if tag_75 != 0x75 {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        Length::decode(reader)?;

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

        Ok(Self(insts))
    }
}
