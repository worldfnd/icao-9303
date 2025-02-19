use {
    super::biometric::*,
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Writer,
    },
};

/// EF.DG2 contains biometric data (face).
///
/// See ICAO-9303-10 4.7.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg2(BiometricInformationGroupTagged<BiometricFace>);

/// Biometric header face information.
/// Is an optional OCTET STRING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricFace(Option<OctetString>);

impl EfDg2 {
    pub fn infos(&self) -> &[BiometricInformation<BiometricFace>] {
        &self.0.infos()
    }
}

impl BiometricType for BiometricFace {
    const GROUP_TAG: u8 = 0x75;
    type Subtype = Self;
    type Data = OctetString; // TODO
}

impl BiometricFace {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|os| os.as_bytes())
    }
}

impl der::FixedTag for BiometricFace {
    const TAG: der::Tag = der::Tag::ContextSpecific {
        constructed: false,
        number:      der::TagNumber::new(2),
    };
}

impl EncodeValue for BiometricFace {
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

impl<'a> DecodeValue<'a> for BiometricFace {
    fn decode_value<R: Reader<'a>>(reader: &mut R, h: der::Header) -> der::Result<Self> {
        let bytes = reader.read_slice(h.length)?;
        Ok(Self(Some(OctetString::new(bytes)?)))
    }
}

impl Encode for EfDg2 {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for EfDg2 {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let group = BiometricInformationGroupTagged::decode(reader)?;
        Ok(Self(group))
    }
}
