use {
    super::{biometric::*, iso19794::*},
    crate::ensure_err,
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, Length, Reader,
        Writer,
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
    type Data = BiometricIrisData;
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

//-----------------------------\\
// ISO 19794-6:2005 structures \\
//-----------------------------\\

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricIrisData {
    pub header:  IrisGeneralHeader,
    pub records: Vec<IrisRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrisGeneralHeader {
    pub format_identifier:     FormatIdentifier, // 4 bytes
    pub version_number:        VersionNumber,    // 4 bytes
    pub records_length:        u32,              // 4 bytes
    pub capture_device_id:     u16,              // 2 bytes
    pub records_count:         u8,               // 1 byte
    pub records_header_length: u16,              // 2 bytes
    pub image_properties:      u16,              // 2 bytes
    pub iris_diameter:         u16,              // 2 bytes
    pub image_format:          u16,              // 2 bytes
    pub raw_image_width:       u16,              // 2 bytes
    pub raw_image_height:      u16,              // 2 bytes
    pub intensity_depth:       u8,               // 1 byte
    pub image_transformation:  u8,               // 1 byte
    pub device_unique_id:      [u8; 16],         // 16 bytes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrisRecord {
    pub biometric_subtype: u8,
    pub count:             u16, // 2 bytes
    pub images:            Vec<IrisImage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrisImage {
    pub image_number: u16,               // 2 bytes
    pub quality: u8,                     // 1 byte
    pub rotation_angle: i16,             // 2 bytes
    pub rotation_angle_uncertainty: u16, // 2 bytes
    pub image_length: u32,               // 4 bytes
    pub data: Vec<u8>,                   // image_length bytes
}

impl<'a> DecodeIso19794<'a> for BiometricIrisData {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = IrisGeneralHeader::decode_iso_19794(reader)?;
        let records = (0..header.records_count)
            .map(|_| IrisRecord::decode_iso_19794(reader))
            .collect::<Result<_, _>>()?;

        Ok(Self { header, records })
    }
}

impl<'a> DecodeIso19794<'a> for IrisGeneralHeader {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 45u8.into(),
            Error::incomplete(reader.position())
        );

        let format_identifier = FormatIdentifier::decode_iso_19794(reader)?;
        let version_number = VersionNumber::decode_iso_19794(reader)?;
        let records_length = u32::decode_iso_19794(reader)?;
        let capture_device_id = u16::decode_iso_19794(reader)?;
        let records_count = reader.read_byte()?;
        let records_header_length = u16::decode_iso_19794(reader)?;
        let image_properties = u16::decode_iso_19794(reader)?;
        let iris_diameter = u16::decode_iso_19794(reader)?;
        let image_format = u16::decode_iso_19794(reader)?;
        let raw_image_width = u16::decode_iso_19794(reader)?;
        let raw_image_height = u16::decode_iso_19794(reader)?;
        let intensity_depth = reader.read_byte()?;
        let image_transformation = reader.read_byte()?;
        let mut device_unique_id = [0u8; 16];
        reader.read_into(&mut device_unique_id)?;

        Ok(Self {
            format_identifier,
            version_number,
            records_length,
            capture_device_id,
            records_count,
            records_header_length,
            image_properties,
            iris_diameter,
            image_format,
            raw_image_width,
            raw_image_height,
            intensity_depth,
            image_transformation,
            device_unique_id,
        })
    }
}

impl<'a> DecodeIso19794<'a> for IrisRecord {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 3u8.into(),
            Error::incomplete(reader.position())
        );

        let biometric_subtype = reader.read_byte()?;
        let count = u16::decode_iso_19794(reader)?;
        let images = (0..count)
            .map(|_| IrisImage::decode_iso_19794(reader))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            biometric_subtype,
            count,
            images,
        })
    }
}

impl<'a> DecodeIso19794<'a> for IrisImage {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 11u8.into(),
            Error::incomplete(reader.position())
        );

        let image_number = u16::decode_iso_19794(reader)?;
        let quality = reader.read_byte()?;
        let rotation_angle = i16::decode_iso_19794(reader)?;
        let rotation_angle_uncertainty = u16::decode_iso_19794(reader)?;
        let image_length = u32::decode_iso_19794(reader)?;
        let data = reader.read_vec(image_length.try_into()?)?;

        Ok(Self {
            image_number,
            quality,
            rotation_angle,
            rotation_angle_uncertainty,
            image_length,
            data,
        })
    }
}
