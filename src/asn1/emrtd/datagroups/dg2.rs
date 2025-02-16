use {
    super::biometric::*,
    der::{self, Decode, Encode, Length, Reader, Writer},
};

/// EF.DG2 contains biometric data (face).
///
/// See ICAO-9303-10 4.7.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg2(BiometricInformationGroupTagged<0x75, BiometricSubtype>);

impl EfDg2 {
    pub fn infos(&self) -> &[BiometricInformation<BiometricSubtype>] {
        &self.0.infos()
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
