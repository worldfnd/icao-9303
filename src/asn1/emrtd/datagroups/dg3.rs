use {
    super::{biometric::*, iso19794::*},
    crate::ensure_err,
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Error, Length, Reader,
        Writer,
    },
};

/// EF.DG3 (optional) contains biometric data (finger).
///
/// See ICAO-9303-10 4.7.3
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg3(BiometricInformationGroupTagged<BiometricFinger>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiometricFinger {
    pub side:   Side,
    pub finger: Finger,
}

impl BiometricType for BiometricFinger {
    const GROUP_TAG: u8 = 0x63;
    type Subtype = Self;
    type Data = BiometricFingerData;
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

impl BiometricInformation<BiometricFinger> {
    pub fn finger(&self) -> BiometricFinger {
        self.header.bsubtype
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

//-----------------------------\\
// ISO 19794-4:2005 structures \\
//-----------------------------\\

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BiometricFingerData {
    pub header:  FingerGeneralHeader,
    pub records: Vec<FingerRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerGeneralHeader {
    pub format_identifier: FormatIdentifier, // 4 bytes
    pub version_number: VersionNumber,       // 4 bytes
    pub records_length: u64,                 // 6 bytes
    pub capture_device_id: u16,              // 2 bytes
    pub acquisition_level: u16,              // 2 bytes
    pub records_count: u8,                   // 1 bytes
    pub scale_units: u8,                     // 1 bytes
    pub scan_resolution_horizontal: u16,     // 2 bytes
    pub scan_resolution_vertical: u16,       // 2 bytes
    pub image_resolution_horizontal: u16,    // 2 bytes
    pub image_resolution_vertical: u16,      // 2 bytes
    pub depth: u8,                           // 1 byte
    pub compression_algorithm: u8,           // 1 byte
    pub reserved: u16,                       // 2 bytes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerRecord {
    header: FingerRecordHeader,
    data:   Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerRecordHeader {
    pub record_length:   u32, // 4 bytes
    pub position:        u8,  // 1 byte
    pub view_count:      u8,  // 1 byte
    pub view_number:     u8,  // 1 byte
    pub quality:         u8,  // 1 byte
    pub impression_type: u8,  // 1 byte
    pub width:           u16, // 2 bytes
    pub height:          u16, // 2 bytes
    pub reserved:        u8,  // 1 byte
}

impl<'a> DecodeIso19794<'a> for BiometricFingerData {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = FingerGeneralHeader::decode_iso_19794(reader)?;
        let records = (0..header.records_count)
            .map(|_| FingerRecord::decode_iso_19794(reader))
            .collect::<Result<_, _>>()?;

        Ok(Self { header, records })
    }
}

impl<'a> DecodeIso19794<'a> for FingerGeneralHeader {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 32u8.into(),
            Error::incomplete(reader.position())
        );

        let format_identifier = FormatIdentifier::decode_iso_19794(reader)?;
        let version_number = VersionNumber::decode_iso_19794(reader)?;

        let mut bytes = [0u8; 8];
        reader.read_into(&mut bytes[2..])?; // read 6 bytes
        let records_length = u64::from_be_bytes(bytes);

        let capture_device_id = u16::decode_iso_19794(reader)?;
        let acquisition_level = u16::decode_iso_19794(reader)?;
        let records_count = reader.read_byte()?;
        let scale_units = reader.read_byte()?;
        let scan_resolution_horizontal = u16::decode_iso_19794(reader)?;
        let scan_resolution_vertical = u16::decode_iso_19794(reader)?;
        let image_resolution_horizontal = u16::decode_iso_19794(reader)?;
        let image_resolution_vertical = u16::decode_iso_19794(reader)?;
        let depth = reader.read_byte()?;
        let compression_algorithm = reader.read_byte()?;
        let reserved = u16::decode_iso_19794(reader)?;

        Ok(Self {
            format_identifier,
            version_number,
            records_length,
            capture_device_id,
            acquisition_level,
            records_count,
            scale_units,
            scan_resolution_horizontal,
            scan_resolution_vertical,
            image_resolution_horizontal,
            image_resolution_vertical,
            depth,
            compression_algorithm,
            reserved,
        })
    }
}

impl<'a> DecodeIso19794<'a> for FingerRecord {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = FingerRecordHeader::decode_iso_19794(reader)?;
        let data_len = header.record_length - 14;
        let data = reader.read_vec(data_len.try_into()?)?;
        Ok(Self { header, data })
    }
}

impl<'a> DecodeIso19794<'a> for FingerRecordHeader {
    fn decode_iso_19794<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        ensure_err!(
            reader.remaining_len() >= 14u8.into(),
            Error::incomplete(reader.position())
        );

        let record_length = u32::decode_iso_19794(reader)?;
        let position = reader.read_byte()?;
        let view_count = reader.read_byte()?;
        let view_number = reader.read_byte()?;
        let quality = reader.read_byte()?;
        let impression_type = reader.read_byte()?;
        let width = u16::decode_iso_19794(reader)?;
        let height = u16::decode_iso_19794(reader)?;
        let reserved = reader.read_byte()?;

        Ok(Self {
            record_length,
            position,
            view_count,
            view_number,
            quality,
            impression_type,
            width,
            height,
            reserved,
        })
    }
}
