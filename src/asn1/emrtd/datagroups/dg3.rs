use {
    super::biometric::*,
    der::{self, Decode, Encode, Length, Reader, Writer},
};

/// EF.DG3 (optional) contains biometric data (finger).
///
/// See ICAO-9303-10 4.7.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg3(BiometricInformationGroupTagged<0x63>);

impl EfDg3 {
    pub fn infos(&self) -> &[BiometricInformation] {
        &self.0.infos()
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
