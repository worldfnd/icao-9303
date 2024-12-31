//! ICAO 9303-10 Table 38.

use {
    der::Tag,
    std::fmt::{self, Display, Formatter},
};

pub const EMRTD_LDS1_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

// Unsupported optional AIDs, mostly requiring terminal authentication.
pub const EMRTD_TRAVEL_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x01];
pub const EMRTD_VISA_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x02];
pub const EMRTD_BIOMETRICS_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x03];

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum DedicatedId {
    MasterFile,
    EmrtdLds1,
    UnknownApplication(Vec<u8>),
}

/// Elementary File Identifiers
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum FileId {
    CardAccess,
    Dir, // Missing from table 38, but included in section 3.11
    AttrInfo,
    CardSecurity,
    Com,
    Dg1,
    Dg2,
    Dg3,
    Dg4,
    Dg5,
    Dg6,
    Dg7,
    Dg8,
    Dg9,
    Dg10,
    Dg11,
    Dg12,
    Dg13,
    Dg14,
    Dg15,
    Dg16,
    Sod,
}

impl DedicatedId {
    pub fn from_aid(aid: &[u8]) -> Self {
        match aid {
            EMRTD_LDS1_AID => Self::EmrtdLds1,
            _ => Self::UnknownApplication(aid.to_vec()),
        }
    }

    pub fn aid(&self) -> Option<&[u8]> {
        match self {
            Self::MasterFile => None,
            Self::EmrtdLds1 => Some(EMRTD_LDS1_AID),
            Self::UnknownApplication(aid) => Some(aid),
        }
    }
}

impl FileId {
    pub fn iter() -> impl Iterator<Item = FileId> {
        [
            Self::CardAccess,
            Self::Dir,
            Self::AttrInfo,
            Self::CardSecurity,
            Self::Com,
            Self::Dg1,
            Self::Dg2,
            Self::Dg3,
            Self::Dg4,
            Self::Dg5,
            Self::Dg6,
            Self::Dg7,
            Self::Dg8,
            Self::Dg9,
            Self::Dg10,
            Self::Dg11,
            Self::Dg12,
            Self::Dg13,
            Self::Dg14,
            Self::Dg15,
            Self::Dg16,
            Self::Sod,
        ]
        .iter()
        .copied()
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Com => "EF.COM",
            Self::CardAccess => "EF.CARDACCESS",
            Self::Dir => "EF.DIR",
            Self::AttrInfo => "EF.ATTR/INFO",
            Self::CardSecurity => "EF.CardSecurity",
            Self::Dg1 => "EF.DG1",
            Self::Dg2 => "EF.DG2",
            Self::Dg3 => "EF.DG3",
            Self::Dg4 => "EF.DG4",
            Self::Dg5 => "EF.DG5",
            Self::Dg6 => "EF.DG6",
            Self::Dg7 => "EF.DG7",
            Self::Dg8 => "EF.DG8",
            Self::Dg9 => "EF.DG9",
            Self::Dg10 => "EF.DG10",
            Self::Dg11 => "EF.DG11",
            Self::Dg12 => "EF.DG12",
            Self::Dg13 => "EF.DG13",
            Self::Dg14 => "EF.DG14",
            Self::Dg15 => "EF.DG15",
            Self::Dg16 => "EF.DG16",
            Self::Sod => "EF.SOD",
        }
    }

    /// ICAO 9303-10 section 3.11
    pub fn parent(&self) -> DedicatedId {
        match self {
            Self::CardAccess | Self::CardSecurity | Self::Dir | Self::AttrInfo => {
                DedicatedId::MasterFile
            }
            _ => DedicatedId::EmrtdLds1,
        }
    }

    pub fn file_id(&self) -> u16 {
        // CardAccess and Sod are the same, but live in different applications.
        match self {
            Self::AttrInfo => 0x2f01,
            Self::Dir => 0x2f00,
            Self::CardAccess => 0x011c,
            Self::CardSecurity => 0x011d,
            Self::Com => 0x011e,
            Self::Dg1 => 0x0101,
            Self::Dg2 => 0x0102,
            Self::Dg3 => 0x0103,
            Self::Dg4 => 0x0104,
            Self::Dg5 => 0x0105,
            Self::Dg6 => 0x0106,
            Self::Dg7 => 0x0107,
            Self::Dg8 => 0x0108,
            Self::Dg9 => 0x0109,
            Self::Dg10 => 0x010a,
            Self::Dg11 => 0x010b,
            Self::Dg12 => 0x010c,
            Self::Dg13 => 0x010d,
            Self::Dg14 => 0x010e,
            Self::Dg15 => 0x010f,
            Self::Dg16 => 0x0110,
            Self::Sod => 0x011d,
        }
    }

    pub fn short_id(&self) -> u8 {
        match self {
            Self::AttrInfo => 0x01,
            Self::Dir => 0x1e,
            Self::CardAccess => 0x1c,
            Self::CardSecurity => 0x1d,
            Self::Com => 0x1e,
            Self::Dg1 => 0x01,
            Self::Dg2 => 0x02,
            Self::Dg3 => 0x03,
            Self::Dg4 => 0x04,
            Self::Dg5 => 0x05,
            Self::Dg6 => 0x06,
            Self::Dg7 => 0x07,
            Self::Dg8 => 0x08,
            Self::Dg9 => 0x09,
            Self::Dg10 => 0x0a,
            Self::Dg11 => 0x0b,
            Self::Dg12 => 0x0c,
            Self::Dg13 => 0x0d,
            Self::Dg14 => 0x0e,
            Self::Dg15 => 0x0f,
            Self::Dg16 => 0x10,
            Self::Sod => 0x1d,
        }
    }

    pub fn tag(&self) -> Tag {
        match self {
            Self::Sod => 0x77.try_into().unwrap(),
            _ => unimplemented!(),
        }
    }
}

impl Display for FileId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
