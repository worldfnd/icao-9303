use {
    super::biometric::*,
    der::{self, Decode, Encode, Length, Reader, Writer},
};

/// EF.DG4 contains biometric data (iris).
///
/// See ICAO-9303-10 4.7.4
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg4(BiometricInformationGroupTagged<0x76>);

impl EfDg4 {
    pub fn infos(&self) -> &[BiometricInformation] {
        &self.0.infos()
    }
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
