use {
    super::{biometric::*, iso19794::*},
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Writer,
    },
};

/// EF.DG4 contains biometric data (iris).
///
/// See ICAO-9303-10 4.7.4
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg4(BiometricInformationGroupTagged<BiometricIris>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiometricIris {
    pub side: Side,
}

impl BiometricType for BiometricIris {
    const GROUP_TAG: u8 = 0x76;
    type Subtype = Self;
    type Data = Vec<u8>; // TODO
}

impl EfDg4 {
    pub fn infos(&self) -> &[BiometricInformation<BiometricIris>] {
        &self.0.infos()
    }
}

impl BiometricInformation<BiometricIris> {
    pub fn iris(&self) -> BiometricIris {
        self.header.bsubtype
    }
}

impl BiometricIris {
    pub fn from_byte(byte: u8) -> Self {
        let side_bits = byte & 0b11;
        Self {
            side: Side::from_bits(side_bits),
        }
    }

    pub fn to_byte(&self) -> u8 {
        self.side as u8
    }
}

impl EncodeValue for BiometricIris {
    fn value_len(&self) -> der::Result<Length> {
        OctetString::value_len(&OctetString::new(&[0])?)
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        OctetString::encode_value(&OctetString::new(&[self.to_byte()])?, encoder)
    }
}

impl<'a> DecodeValue<'a> for BiometricIris {
    fn decode_value<R: Reader<'a>>(reader: &mut R, h: der::Header) -> der::Result<Self> {
        // input OCTET STRING bytes value
        let bytes = reader.read_slice(h.length)?;
        Ok(BiometricIris::from_byte(bytes.last().copied().unwrap()))
    }
}

impl der::FixedTag for BiometricIris {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: false,
        number:      der::TagNumber::new(2),
    };
}

impl Encode for EfDg4 {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for EfDg4 {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let group = BiometricInformationGroupTagged::decode(reader)?;
        Ok(Self(group))
    }
}
