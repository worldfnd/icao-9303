//! ISO/IEC 7816-4 section 5.6

use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct StatusWord(u16);

impl StatusWord {
    pub const SUCCESS: StatusWord = StatusWord(0x9000);
    pub const FILE_NOT_FOUND: StatusWord = StatusWord(0x6a82);
    pub const ACCESS_DENIED: StatusWord = StatusWord(0x6982);

    pub const SECURE_MESSAGING_INCOMPLETE: StatusWord = StatusWord(0x6987);
    pub const SECURE_MESSAGING_INCORRECT: StatusWord = StatusWord(0x6988);

    pub fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub fn sw2(self) -> u8 {
        (self.0 & 0xff) as u8
    }

    pub fn is_success(self) -> bool {
        matches!(self.0, 0x9000 | 0x6100..=0x61ff)
    }

    pub fn data_remaining(self) -> Option<usize> {
        match self.0 {
            0x6100..=0x61ff => Some(self.0 as usize & 0xff),
            _ => None,
        }
    }

    pub fn is_valid(self) -> bool {
        matches!(self.0, 0x6100..=0x6FFF | 0x9000..=0x9FFF)
    }

    pub fn is_warning(self) -> bool {
        matches!(self.0, 0x6200..=0x63ff)
    }

    /// Note: If the this is the status, the data must be absent.
    pub fn is_error(self) -> bool {
        matches!(self.0, 0x6400..=0x6fff)
    }

    pub fn is_execution_error(self) -> bool {
        matches!(self.0, 0x6400..=0x65ff)
    }

    pub fn is_checking_error(self) -> bool {
        matches!(self.0, 0x6700..=0x6fff)
    }

    pub fn class_as_str(self) -> &'static str {
        match self.0 {
            0x9000 | 0x6100..=0x61ff => "Success",
            0x6200..=0x63ff => "Warning",
            0x6400..=0x66ff => "Execution error",
            0x6700..=0x6fff => "Checking error",
            0x9000..=0x9fff => "Unknown",
            _ => "Invalid",
        }
    }

    pub fn as_str(self) -> &'static str {
        // See ISO/IEC 7816-4 section 5.6
        #[allow(clippy::match_overlapping_arm)] // Used for catch-alls
        match self.0 {
            0x9000 => "Success",
            0x9000..=0x9fff => "Unknown proprietary status word",
            0x6100..=0x61ff => "Success, data remaining",

            // Non-modifying warnings
            0x6200 => "Unspecified non-modifying warning",
            0x6202..=0x6280 => "Query pending (see ISO 7816-4 section 12.6.2",
            0x6281 => "Part of returned data may be corrupted",
            0x6282 => "End of file/record reached before reading Le bytes, or unsuccessful search",
            0x6283 => "Selected file invalidated",
            0x6284 => {
                "Faile or data control information not formatted according to ISO 7816-4 section \
                 7.4"
            }
            0x6285 => "Selected file or data object in termination state",
            0x6286 => "No input data available from a sensor on the card",
            0x6287 => "At least one of the referenced records is not processed",
            0x6200..=0x62ff => "Unknown non-modifying warning", // Catch all

            // Modifying warnings
            0x6300 => "Unspecified modifying warning",
            0x6340 => "Unsuccessful comparison",
            0x6381 => "File or data object filled up by last write",
            0x63c0..=0x63cf => "Counter value", // Command specific, e.g. number of allowed
            // retries.
            0x6300..=0x63ff => "Unknown modifying warning", // Catch all

            // Non-modifying execution errors
            0x6400 => "Unspecified non-modifying execution error",
            0x6401 => "Immediate response required by the card",
            0x6402..=0x6480 => "Query pending (see ISO 7816-4 section 12.6.2",
            0x6481 => "Logical shared access denied",
            0x6482 => "Logical channel opening denied",
            0x6400..=0x64ff => "Unknown non-modifying execution error", // Catch all

            // Modifying execution errors
            0x6500 => "Unspecified modifying execution error",
            0x6581 => "Memory failure",
            0x6500..=0x65ff => "Unknown modifying execution error", // Catch all

            // Security execution errors
            0x6600 => "Unspecified securtiy execution error",
            0x6600..=0x66ff => "Unknown reserved security execution error", // Catch all

            // Checking errors
            0x6700 => "Unspecified wrong length error",
            0x6701 => "Command format not compliant with ISO 7816-4 section 5.1",
            0x6702 => "Unexpected value of Lc",
            0x6700..=0x67ff => "Unknown wrong length error",

            0x6800 => "Unspecified function in class not supported error",
            0x6801 => "Logical channel not supported",
            0x6802 => "Secure messaging not supported",
            0x6803 => "Last command of the chain expected",
            0x6804 => "Command chaining not supported",
            0x6800..=0x68ff => "Unknown function in class not supported error", // Catch all

            0x6900 => "Unspecified command not allowed error",
            0x6981 => "Command incompatible with file structure",
            0x6982 => "Security status not satisfied",
            0x6983 => "Authentication method blocked",
            0x6984 => "Referenced data not usable",
            0x6985 => "Conditions of use not satisfied",
            0x6986 => "Command not allowed (no current EF)",
            0x6987 => "Expected secure messaging data objects missing",
            0x6988 => "Incorrect secure messaging data objects",
            0x6900..=0x69ff => "Unknown command not allowed error", // Catch all

            0x6a00 => "Unspecified wrong parameters error",
            0x6a80 => "Incorrect parameters in the data field",
            0x6a81 => "Function not supported",
            0x6a82 => "File or application not found",
            0x6a83 => "Record not found",
            0x6a84 => "Not enough memory space in the file",
            0x6a85 => "Lc inconsistent with tag-length-value structure",
            0x6a86 => "Incorrect P1 or P2 parameter",
            0x6a87 => "Lc inconsistent with P1-P2",
            0x6a88 => "Referenced data not found",
            0x6a89 => "File already exists",
            0x6a8a => "DF name already exists",
            0x6a00..=0x6b00 => "Unknown wrong parameters error", // Catch all

            0x6c00..=0x6cff => "Wrong Le field", // 2nd byte is the correct length

            0x6d00 => "Instruction code not supported or invalid",
            0x6e00 => "Class not supported",
            0x6f00 => "No precise diagnosis",
            0x6700..=0x6fff => "Unknown checking error", // Catch all

            _ => "Invalid status word",
        }
    }
}

impl Display for StatusWord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "[{:04X}] {}: {}",
            self.0,
            self.class_as_str(),
            self.as_str()
        )
    }
}

impl From<u16> for StatusWord {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<StatusWord> for u16 {
    fn from(value: StatusWord) -> u16 {
        value.0
    }
}
