//! ISO 19794:2005 decode utils.
//! Encoded data has no record separators or field tags; fields are parsed by
//! byte count.

use {
    crate::ensure_err,
    der::{Error, ErrorKind, Reader},
};

/// ISO 19794:2005 General Header
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralHeader {
    pub format_identifier:         String, // 4 bytes
    pub version_number:            String, // 4 bytes
    pub record_length:             u32,    // 4 bytes
    pub number_of_representations: u16,    // 2 bytes
}

/// Decode ISO 19794
/// While this encoding does not follow DER rules, we use [`der::Reader`] since
/// data will be included in the `Reader` of the DER-encoded ICAO 9303-10
/// Biometric data headers.
pub trait DecodeIso19794<'a>: Sized {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error>;
}

impl<'a> DecodeIso19794<'a> for GeneralHeader {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        ensure_err!(
            reader.remaining_len() >= 14u8.into(),
            Error::incomplete(reader.remaining_len())
        );

        // Format identifier and version number are null-terminated
        let format_identifier = String::from_utf8(reader.read_slice(4u8.into())?[0..3].to_vec())?;
        let version_number = String::from_utf8(reader.read_slice(4u8.into())?[0..3].to_vec())?;

        let record_length = u32::decode_iso_19794(reader)?;
        let number_of_representations = u16::decode_iso_19794(reader)?;

        Ok(GeneralHeader {
            format_identifier,
            version_number,
            record_length,
            number_of_representations,
        })
    }
}

impl<'a> DecodeIso19794<'a> for u16 {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        Ok(u16::from_be_bytes(
            reader
                .read_slice(2u8.into())?
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Failed, reader.position()))?,
        ))
    }
}

impl<'a> DecodeIso19794<'a> for u32 {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        Ok(u32::from_be_bytes(
            reader
                .read_slice(4u8.into())?
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Failed, reader.position()))?,
        ))
    }
}

impl<'a> DecodeIso19794<'a> for Vec<u8> {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        reader.read_vec(reader.remaining_len())
    }
}
