use {
    super::{biometric::*, iso19794::*},
    crate::ensure_err,
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, Length, Reader,
        Writer,
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

impl BiometricType for BiometricFace {
    const GROUP_TAG: u8 = 0x75;
    type Subtype = Self;
    type Data = BiometricFaceData;
}

impl EfDg2 {
    pub fn infos(&self) -> &[BiometricInformation<BiometricFace>] {
        &self.0.infos()
    }
}

impl BiometricFace {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|os| os.as_bytes())
    }
}

impl BiometricInformation<BiometricFace> {
    pub fn representations(&self) -> &[FaceRepresentation] {
        &self.data.0.representations
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

//-----------------------------\\
// ISO 19794-5:2005 structures \\
//-----------------------------\\

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricFaceData {
    pub general_header:  GeneralHeader,
    pub representations: Vec<FaceRepresentation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaceRepresentation {
    // Representation Header fields
    pub face_information:  FacialInformation,
    pub feature_points:    Vec<FeaturePoint>,
    pub image_information: ImageInformation,
    pub image_data:        Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FacialInformation {
    pub record_length:          u32,     // 4
    pub feature_point_count:    u16,     // 2 bytes
    pub gender:                 u8,      // 1 byte
    pub eye_colour:             u8,      // 1 byte
    pub hair_colour:            u8,      // 1 byte
    pub feature_mask:           [u8; 3], // 3 bytes
    pub expression_mask:        u16,     // 2 bytes
    pub pose_angle:             [u8; 3], // 3 bytes
    pub pose_angle_uncertainty: [u8; 3], // 3 bytes
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeaturePoint {
    pub feature_type: u8,  // 1 byte
    pub feature_code: u8,  // 1 byte
    pub x_coord:      u16, // 2 bytes
    pub y_coord:      u16, // 2 bytes
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageInformation {
    pub face_image_type: u8,            // 1 byte
    pub image_data_type: ImageDataType, // 1 byte
    pub width:           u16,           // 2 bytes
    pub height:          u16,           // 2 bytes
    pub color_space:     u8,            // 1 byte
    pub source_type:     u8,            // 1 byte
    pub device_type:     u16,           // 2 bytes
    pub quality:         u16,           // 2 bytes
}

#[repr(u8)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageDataType {
    Jpeg     = 0x00,
    Jpeg2000 = 0x01,
    Reserved(u8),
}

impl<'a> DecodeIso19794<'a> for BiometricFaceData {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let general_header = GeneralHeader::decode_iso_19794(reader)?;
        let mut representations =
            Vec::with_capacity(general_header.number_of_representations.into());
        for _ in 0..general_header.number_of_representations {
            let representation = FaceRepresentation::decode_iso_19794(reader)?;
            representations.push(representation);
        }

        Ok(Self {
            general_header,
            representations,
        })
    }
}

impl<'a> DecodeIso19794<'a> for FaceRepresentation {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        // Header
        let face_information = FacialInformation::decode_iso_19794(reader)?; // 20 bytes
        let feature_points = (0..face_information.feature_point_count)
            .map(|_| FeaturePoint::decode_iso_19794(reader))
            .collect::<Result<Vec<_>, _>>()?; // 8x bytes
        let image_information = ImageInformation::decode_iso_19794(reader)?; // 12 bytes

        // Data
        let data_len = face_information.record_length - (20 + 8 * feature_points.len() as u32 + 12);
        let image_data = reader.read_vec(data_len.try_into()?)?;

        Ok(Self {
            face_information,
            feature_points,
            image_information,
            image_data,
        })
    }
}

impl<'a> DecodeIso19794<'a> for FacialInformation {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 20u8.into(),
            Error::incomplete(reader.remaining_len())
        );

        let position = reader.position();
        let slice_err = move |_: std::array::TryFromSliceError| {
            der::Error::new(der::ErrorKind::Failed, position)
        };

        let record_length = u32::decode_iso_19794(reader)?;
        let feature_point_count = u16::decode_iso_19794(reader)?;
        let gender = reader.read_byte()?;
        let eye_colour = reader.read_byte()?;
        let hair_colour = reader.read_byte()?;
        let feature_mask = reader
            .read_slice(3u8.into())?
            .try_into()
            .map_err(slice_err)?;
        let expression_mask = u16::decode_iso_19794(reader)?;
        let pose_angle = reader
            .read_slice(3u8.into())?
            .try_into()
            .map_err(slice_err)?;
        let pose_angle_uncertainty = reader
            .read_slice(3u8.into())?
            .try_into()
            .map_err(slice_err)?;

        Ok(Self {
            record_length,
            feature_point_count,
            gender,
            eye_colour,
            hair_colour,
            feature_mask,
            expression_mask,
            pose_angle,
            pose_angle_uncertainty,
        })
    }
}

impl<'a> DecodeIso19794<'a> for FeaturePoint {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let feature_type = reader.read_byte()?;
        let feature_code = reader.read_byte()?;
        let x_coord = u16::decode_iso_19794(reader)?;
        let y_coord = u16::decode_iso_19794(reader)?;
        let _reserved = reader.read_slice(2u8.into())?;

        Ok(Self {
            feature_type,
            feature_code,
            x_coord,
            y_coord,
        })
    }
}

impl<'a> DecodeIso19794<'a> for ImageInformation {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let face_image_type = reader.read_byte()?;
        let image_data_type = match reader.read_byte()? {
            0x00 => ImageDataType::Jpeg,
            0x01 => ImageDataType::Jpeg2000,
            other => ImageDataType::Reserved(other),
        };
        let width = u16::decode_iso_19794(reader)?;
        let height = u16::decode_iso_19794(reader)?;
        let color_space = reader.read_byte()?;
        let source_type = reader.read_byte()?;
        let device_type = u16::decode_iso_19794(reader)?;
        let quality = u16::decode_iso_19794(reader)?;

        Ok(Self {
            face_image_type,
            image_data_type,
            width,
            height,
            color_space,
            source_type,
            device_type,
            quality,
        })
    }
}
