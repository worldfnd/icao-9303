//! ISO 19794:2005 decode utils.
//! Encoded data has no record separators or field tags; fields are parsed by
//! byte count.

use {
    crate::ensure_err,
    der::{Error, ErrorKind, Reader},
};

/// Decode ISO 19794
/// While this encoding does not follow DER rules, we use [`der::Reader`] since
/// data will be included in the `Reader` of the DER-encoded ICAO 9303-10
/// Biometric data headers.
pub trait DecodeIso19794<'a>: Sized {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatIdentifier(String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionNumber(String);

impl<'a> DecodeIso19794<'a> for FormatIdentifier {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        String::from_utf8(reader.read_slice(4u8.into())?[0..3].to_vec())
            .map_err(Into::into)
            .map(Self)
    }
}

impl<'a> DecodeIso19794<'a> for VersionNumber {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> Result<Self, Error> {
        String::from_utf8(reader.read_slice(4u8.into())?[0..3].to_vec())
            .map_err(Into::into)
            .map(Self)
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
