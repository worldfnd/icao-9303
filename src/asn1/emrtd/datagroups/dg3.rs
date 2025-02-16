use {
    super::biometric::*,
    anyhow::anyhow,
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind,
        Length, Reader, Writer,
    },
};

/// EF.DG3 (optional) contains biometric data (finger).
///
/// See ICAO-9303-10 4.7.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg3(BiometricInformationGroupTagged<0x63, BiometricFinger>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiometricFinger {
    pub side:   Side,
    pub finger: Finger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandSide {
    NoInformation = 0b00,
    Right         = 0b01,
    Left          = 0b10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finger {
    NoInformation = 0b000,
    Thumb         = 0b001,
    Pointer       = 0b010,
    Middle        = 0b011,
    Ring          = 0b100,
    Little        = 0b101,
}

impl EfDg3 {
    pub fn infos(&self) -> &[BiometricInformation<BiometricFinger>] {
        &self.0.infos()
    }
}

impl BiometricFinger {
    pub fn from_byte(byte: u8) -> Self {
        let side_bits = byte & 0b11;
        let finger_bits = (byte >> 2) & 0b111;
        Self {
            side:   Side::from_bits(side_bits),
            finger: Finger::from_bits(finger_bits),
        }
    }

    pub fn to_byte(&self) -> u8 {
        0x00 | self.side as u8 | ((self.finger as u8) << 2)
    }
}

impl EncodeValue for BiometricFinger {
    fn value_len(&self) -> der::Result<Length> {
        OctetString::value_len(&OctetString::new(&[0])?)
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        OctetString::encode_value(&OctetString::new(&[self.to_byte()])?, encoder)
    }
}

impl<'a> DecodeValue<'a> for BiometricFinger {
    fn decode_value<R: Reader<'a>>(reader: &mut R, h: der::Header) -> der::Result<Self> {
        // input OCTET STRING bytes value
        let bytes = reader.read_slice(h.length)?;
        Ok(BiometricFinger::from_byte(bytes.last().copied().unwrap()))
    }
}

impl der::FixedTag for BiometricFinger {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: false,
        number:      der::TagNumber::new(2),
    };
}

impl BiometricSubtyped for BiometricFinger {}

impl Finger {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b111 {
            0b001 => Finger::Thumb,
            0b010 => Finger::Pointer,
            0b011 => Finger::Middle,
            0b100 => Finger::Ring,
            0b101 => Finger::Little,
            _ => Finger::NoInformation,
        }
    }
}

impl Encode for EfDg3 {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for EfDg3 {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let group = BiometricInformationGroupTagged::decode(reader)?;
        Ok(Self(group))
    }
}
