use der::{
    self,
    asn1::{OctetStringRef, PrintableString},
    Decode, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag, Header, Length, Reader, Tag,
    TagNumber, Writer,
};

/// EF.ATR/INFO is composed of a [`CardCapabilities`] and a
/// [`ExtendedLengthInformation`] structures.
///
/// See ICAO-9303-10 3.11.1, Table 29.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfAtrInfo {
    pub capabilities:         CardCapabilities,
    pub extended_length_info: Option<ExtendedLengthInformation>,
}

/// Methods available in the card for supporting services.
///
/// See ICAO-9303-10 3.11.1, Table 29.
/// See also ISO 7816-4 8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardCapabilities([u8; 3]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedLengthInformation {
    /// Maximum number of bytes in a command APDU.
    /// Must be at least 1000 for LDS2
    pub command_apdu_max_bytes:  u64,
    /// Maximum number of bytes expected in the response APDU.
    /// Must be at least 1000 for LDS2
    pub response_apdu_max_bytes: u64,
}

impl CardCapabilities {
    // byte 1

    /// DF selection by full DF name
    pub fn df_selection_by_full_name(&self) -> bool {
        self.0[0] & 0x80 != 0
    }

    /// DF selection by full DF name
    pub fn df_selection_by_partial_name(&self) -> bool {
        self.0[0] & 0x40 != 0
    }

    /// DF selection by path
    pub fn df_selection_by_path(&self) -> bool {
        self.0[0] & 0x20 != 0
    }

    /// DF selection by file identifier
    pub fn df_selection_by_file_id(&self) -> bool {
        self.0[0] & 0x10 != 0
    }

    /// DF selection implicit
    pub fn df_selection_implicit(&self) -> bool {
        self.0[0] & 0x08 != 0
    }

    /// Short EF identifier supported
    pub fn short_ef_id_support(&self) -> bool {
        self.0[0] & 0x04 != 0
    }

    /// Record number supported
    pub fn record_number_support(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Record identifier supported
    pub fn record_id_support(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    // byte 2
    // TODO bits 8..=5

    /// Number of quartets (2 quartets = 1 byte) that represent each data unit
    pub fn data_unit_quartets(&self) -> usize {
        let power = self.0[1] & 0x0f;
        1 << power
    }

    /// One-byte data unit size
    pub fn data_unit_one_byte(&self) -> bool {
        self.data_unit_quartets() == 2
    }

    // byte 3
    // TODO bits 5..=1

    /// Command chaining supported
    pub fn command_chaining_support(&self) -> bool {
        self.0[2] & 0x80 != 0
    }

    /// Extended Lc and Le fields supported
    pub fn extended_lc_and_le_fields(&self) -> bool {
        self.0[2] & 0x40 != 0
    }

    /// Extended length information in EF.ATR/INFO
    pub fn extended_length_info_in_atrinfo(&self) -> bool {
        self.0[2] & 0x20 != 0
    }
}

impl FixedTag for CardCapabilities {
    const TAG: Tag = Tag::Application {
        constructed: false,
        number:      TagNumber::new(7), // 0x47
    };
}

impl EncodeValue for EfAtrInfo {
    fn value_len(&self) -> der::Result<Length> {
        todo!("EF.ATR/INFO encoding not supported yet");
    }

    fn encode_value(&self, _encoder: &mut impl Writer) -> der::Result<()> {
        todo!("EF.ATR/INFO encoding not supported yet");
    }
}

// The `der` crate currently only supports single-octet tags, so we parse some
// stuff manually.
impl<'a> Decode<'a> for EfAtrInfo {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag_47 = reader.read_byte()?;
        if tag_47 != CardCapabilities::TAG.into() {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        Length::decode(reader)?;
        let capabilities =
            CardCapabilities(reader.read_slice(Length::new(3))?.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::Value {
                        tag: CardCapabilities::TAG,
                    },
                    reader.position(),
                )
            })?);

        let extended_length_info = if !reader.remaining_len().is_zero()
            && capabilities.extended_length_info_in_atrinfo()
        {
            let tag_7f66 = reader.read_slice(Length::new(2))?;
            if tag_7f66 != &[0x7f, 0x66] {
                return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
            };
            Length::decode(reader)?;
            Some(ExtendedLengthInformation {
                command_apdu_max_bytes:  u64::decode(reader)?,
                response_apdu_max_bytes: u64::decode(reader)?,
            })
        } else {
            None
        };

        // Ignore any remaining data
        if !reader.remaining_len().is_zero() {
            reader.read_slice(reader.remaining_len())?;
        }

        Ok(Self {
            capabilities,
            extended_length_info,
        })
    }
}
