use {
    anyhow::{bail, Result},
    der::{self, Any, Decode, Encode, Length, Reader, Writer},
    std::fmt::{self, Display},
};

const FILLER: char = '<';

/// EF.DG1 containts the MRZ data. It is a `0x5F1F`-tagged ASCII byte array.
/// The `der` crate currently only supports single-octet tags, so we parse
/// everything as `Any`.
///
/// See ICAO-9303-10 4.7.1
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDg1(Any);

impl EfDg1 {
    /// Raw MRZ data
    pub fn as_bytes(&self) -> &[u8] {
        // TODO check initial tag/len OR implement multi-byte tag decoding
        &self.0.value()[3..]
    }

    /// Parse DG1 data into a [`MrzDataRef`]
    pub fn data(&self) -> Result<MrzDataRef> {
        MrzDataRef::from_bytes(self.as_bytes())
    }
}

impl Display for EfDg1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_bytes()))
    }
}

/// Gender as specified in MRZ
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Gender {
    Male,
    Female,
    Unspecified,
}

/// MRZ format
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocumentType {
    TD1, // 3 lines, 30 chars each
    TD2, // 2 lines, 36 chars each
    TD3, // 2 lines, 44 chars each
}

/// MRZ data, with borrowed values
#[derive(Debug)]
pub struct MrzDataRef<'a> {
    pub raw:                  &'a str,
    pub doc_type:             DocumentType,
    pub doc_code:             &'a str,
    pub issuing_state:        &'a str,
    pub primary_identifier:   &'a str,
    pub secondary_identifier: &'a str,
    pub nationality:          &'a str,
    pub doc_number:           &'a str,
    pub date_of_birth:        &'a str,
    pub gender:               Gender,
    pub date_of_expiry:       &'a str,
    pub optional_data1:       &'a str,
    pub optional_data2:       Option<&'a str>,
}

/// MRZ data, with owned values
#[derive(Debug, Clone)]
pub struct MrzData {
    pub raw:                  String,
    pub doc_type:             DocumentType,
    pub doc_code:             String,
    pub issuing_state:        String,
    pub primary_identifier:   String,
    pub secondary_identifier: String,
    pub nationality:          String,
    pub doc_number:           String,
    pub date_of_birth:        String,
    pub gender:               Gender,
    pub date_of_expiry:       String,
    pub optional_data1:       String,
    pub optional_data2:       Option<String>,
}

impl<'a> MrzDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self> {
        let raw_data = std::str::from_utf8(data)?;

        match raw_data.len() {
            90 => Self::parse_td1(raw_data),
            72 => Self::parse_td2(raw_data),
            88 => Self::parse_td3(raw_data),
            _ => bail!("Unknown document type"),
        }
    }

    pub fn parse(s: &'a str) -> Result<Self> {
        Self::from_bytes(s.as_bytes())
    }

    pub fn to_owned(&self) -> MrzData {
        MrzData {
            raw:                  self.raw.to_string(),
            doc_type:             self.doc_type.clone(),
            doc_code:             self.doc_code.to_string(),
            issuing_state:        self.issuing_state.to_string(),
            primary_identifier:   self.primary_identifier.to_string(),
            secondary_identifier: self.secondary_identifier.to_string(),
            nationality:          self.nationality.to_string(),
            doc_number:           self.doc_number.to_string(),
            date_of_birth:        self.date_of_birth.to_string(),
            gender:               self.gender.clone(),
            date_of_expiry:       self.date_of_expiry.to_string(),
            optional_data1:       self.optional_data1.to_string(),
            optional_data2:       self.optional_data2.map(|s| s.to_string()),
        }
    }

    fn parse_td1(raw: &'a str) -> Result<Self> {
        // First line
        let doc_code = &raw[0..2];
        let issuing_state = &raw[2..5];
        let doc_number = raw[5..14].trim_end_matches(FILLER);
        // [15] check digit - docno
        let optional_data1 = raw[15..30].trim_end_matches(FILLER);

        // Second line
        let date_of_birth = &raw[30..36];
        // [36] check digit - birth
        let gender = match raw.chars().nth(37) {
            Some('M') => Gender::Male,
            Some('F') => Gender::Female,
            _ => Gender::Unspecified,
        };
        let date_of_expiry = &raw[38..44];
        // [45] check digit - expiry
        let nationality = &raw[45..48];
        let optional_data2 = Some(raw[48..59].trim_end_matches(FILLER));
        // [59] composite check digit

        // Third line (name)
        let name_line = raw[60..90].trim_end_matches(FILLER);
        let (primary, secondary) = Self::split_name(name_line);

        Ok(Self {
            raw,
            doc_type: DocumentType::TD1,
            doc_code,
            issuing_state,
            primary_identifier: primary,
            secondary_identifier: secondary,
            nationality,
            doc_number,
            date_of_birth,
            gender,
            date_of_expiry,
            optional_data1,
            optional_data2,
        })
    }

    fn parse_td2(raw: &'a str) -> Result<Self> {
        // First line
        let doc_code = &raw[0..2];
        let issuing_state = &raw[2..5];
        let name_line = raw[5..36].trim_end_matches(FILLER);
        let (primary, secondary) = Self::split_name(name_line);

        // Second line
        let doc_number = raw[36..45].trim_end_matches(FILLER);
        // [45] check digit - docno
        let nationality = &raw[46..49];
        let date_of_birth = &raw[49..55];
        // [55] check digit - birth
        let gender = match raw.chars().nth(56) {
            Some('M') => Gender::Male,
            Some('F') => Gender::Female,
            _ => Gender::Unspecified,
        };
        let date_of_expiry = &raw[57..63];
        // [63] check digit - expiry
        let optional_data1 = raw[64..71].trim_end_matches(FILLER);
        // [71] composite check digit

        Ok(Self {
            raw,
            doc_type: DocumentType::TD2,
            doc_code,
            issuing_state,
            primary_identifier: primary,
            secondary_identifier: secondary,
            nationality,
            doc_number,
            date_of_birth,
            gender,
            date_of_expiry,
            optional_data1,
            optional_data2: None,
        })
    }

    fn parse_td3(raw: &'a str) -> Result<Self> {
        // First line
        let doc_code = &raw[0..2];
        let issuing_state = &raw[2..5];
        let name_line = raw[5..44].trim_end_matches(FILLER);
        let (primary, secondary) = Self::split_name(name_line);

        // Second line
        let doc_number = raw[44..53].trim_end_matches(FILLER);
        // [53] check digit - docno
        let nationality = &raw[54..57];
        let date_of_birth = &raw[57..63];
        // [63] check digit - birth
        let gender = match raw.chars().nth(64) {
            Some('M') => Gender::Male,
            Some('F') => Gender::Female,
            _ => Gender::Unspecified,
        };
        let date_of_expiry = &raw[65..71];
        // [71] check digit - expiry
        let optional_data1 = raw[72..86].trim_end_matches(FILLER);
        // [86] check digit
        // [87] composite check digit

        Ok(Self {
            raw,
            doc_type: DocumentType::TD3,
            doc_code,
            issuing_state,
            primary_identifier: primary,
            secondary_identifier: secondary,
            nationality,
            doc_number,
            date_of_birth,
            gender,
            date_of_expiry,
            optional_data1,
            optional_data2: None,
        })
    }

    fn split_name(name: &'a str) -> (&'a str, &'a str) {
        match name.split("<<").collect::<Vec<&str>>().as_slice() {
            [primary, secondary] => (
                primary.trim_end_matches(FILLER),
                secondary.trim_end_matches(FILLER),
            ),
            [primary] => (primary.trim_end_matches(FILLER), ""),
            _ => ("", ""),
        }
    }
}

impl Encode for EfDg1 {
    fn encoded_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> Decode<'a> for EfDg1 {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        Ok(Self(Any::decode(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ICAO 9303-10
    #[test]
    fn test_ef_dg1_mrz_p10_example_a21() {
        let bytes = "I<NLDXI85935F86999999990<<<<<<7208148F1108268NLD<<<<<<<<<<<4VAN<DER<STEEN<<MARIANNE<LOUISE".as_bytes();
        let data = MrzDataRef::from_bytes(bytes).unwrap();
        assert_eq!(data.doc_type, DocumentType::TD1);
        assert_eq!(data.date_of_birth, "720814");
        assert_eq!(data.nationality, "NLD");
        assert_eq!(data.secondary_identifier, "MARIANNE<LOUISE");
        assert_eq!(data.date_of_expiry, "110826");
    }

    // ICAO 9303-6
    #[test]
    fn test_ef_dg1_mrz_p6_example_a() {
        let s = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6";
        let data = MrzDataRef::parse(s).unwrap();
        assert_eq!(data.doc_type, DocumentType::TD2);
        assert_eq!(data.date_of_birth, "740812");
        assert_eq!(data.nationality, "UTO");
        assert_eq!(data.secondary_identifier, "ANNA<MARIA");
        assert_eq!(data.date_of_expiry, "120415");
    }

    // ICAO 9303-4
    #[test]
    fn test_ef_dg1_mrz_p4_example_a() {
        let s = "PPUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let data = MrzDataRef::parse(s).unwrap();
        assert_eq!(data.doc_type, DocumentType::TD3);
        assert_eq!(data.date_of_birth, "740812");
        assert_eq!(data.nationality, "UTO");
        assert_eq!(data.secondary_identifier, "ANNA<MARIA");
        assert_eq!(data.date_of_expiry, "120415");
    }
}
