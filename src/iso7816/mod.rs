mod status_word;

pub use self::status_word::StatusWord;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid APDU: Lc is zero.")]
    LcZero,

    #[error("Invalid APDU: Less than 4 bytes.")]
    ApduTooShort,

    #[error("Invalid APDU: Trailing bytes.")]
    ApduTooLong,

    #[error("Invalid Extended APDU: Lc is zero.")]
    ExtendedLcZero,

    #[error("Invalid Extended APDU: Trailing bytes.")]
    ExtendedApduTooLong,

    #[error("Failed building APDU: {0}")]
    BuildFailure(#[from] anyhow::Error),
}

// TODO handle extended lengths
#[derive(Debug, Clone)]
pub struct Apdu {
    header:       [u8; 4],
    data:         Vec<u8>,
    rlen:         Option<u8>,
    dynamic_auth: bool,
}

impl Apdu {
    /// Creates an empty APDU, with an expected response length `rlen`.
    /// If `rlen` is `None`, then a response of 256 bytes is assumed.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, rlen: Option<u8>) -> Self {
        let header = [cla, ins, p1, p2];
        // Lets assume a short APDU by default
        let data = Vec::with_capacity(255);
        Self {
            header,
            data,
            rlen,
            dynamic_auth: false,
        }
    }

    /// Pushes bytes into the APDU data field. Constructs a TLV sequence.
    pub fn push_tlv(&mut self, tag: u8, data: &[u8]) -> anyhow::Result<&mut Self> {
        let len = u8::try_from(data.len())?;
        self.data.push(tag);
        self.data.push(len);
        self.data.extend_from_slice(data);
        Ok(self)
    }

    /// Pushes raw bytes into the APDU data field.
    pub fn push_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.data.extend_from_slice(data);
        self
    }

    pub fn dynamic_auth(&mut self) -> &mut Self {
        self.dynamic_auth = true;
        self
    }

    /// Command chaining. Must be called if this is not the last APDU in the
    /// chain.
    pub fn chain(&mut self) -> &mut Self {
        self.header[0] |= 0x10;
        self
    }

    pub fn build(&self) -> anyhow::Result<Vec<u8>> {
        // le == 0x00 equates to a 256 bytes response
        let dyn_auth_len: u8 = if self.dynamic_auth { 2 } else { 0 };
        let data_len = u8::try_from(self.data.len())?;
        let le_present = self.rlen.is_some_and(|len| len != 0) || self.rlen.is_none();
        let len = 4 // header
            + (dyn_auth_len + data_len != 0) as usize  // lc
            + dyn_auth_len as usize
            + data_len as usize
            + le_present as usize;

        let mut apdu = Vec::with_capacity(len);
        // header
        apdu.extend_from_slice(&self.header);
        // lc
        if dyn_auth_len + data_len != 0 {
            apdu.push((dyn_auth_len + data_len).try_into()?);
        }
        // data
        if self.dynamic_auth {
            apdu.push(0x7c);
            apdu.push(data_len);
        }
        if self.data.len() > 0 {
            apdu.extend_from_slice(&self.data);
        }
        // le
        if le_present {
            apdu.push(self.rlen.unwrap_or(0));
        }

        Ok(apdu)
    }
}

#[derive(Debug)]
pub struct ApduRef<'a> {
    pub header: &'a [u8],
    pub lc:     &'a [u8],
    pub data:   &'a [u8],
    pub le:     &'a [u8],
}

impl ApduRef<'_> {
    pub fn cla(&self) -> u8 {
        self.header[0]
    }

    pub fn ins(&self) -> u8 {
        self.header[1]
    }

    pub fn p1(&self) -> u8 {
        self.header[2]
    }

    pub fn p2(&self) -> u8 {
        self.header[3]
    }

    pub fn is_extended_length(&self) -> bool {
        self.lc.len() > 1 || self.le.len() > 1
    }
}

/// Parse APDU into header, Lc, data, and Le.
/// See ISO 7816-4 section 5.2
pub fn parse_apdu(apdu: &[u8]) -> Result<ApduRef, Error> {
    let empty = &apdu[0..0];
    Ok(match (apdu.len(), apdu.get(4)) {
        (0..4, _) => return Err(Error::ApduTooShort),
        // Short without data and no Le
        (4, None) => ApduRef {
            header: &apdu[..4],
            lc:     empty,
            data:   empty,
            le:     empty,
        },
        // Short without data and with Le
        (5, _) => ApduRef {
            header: &apdu[..4],
            lc:     empty,
            data:   empty,
            le:     &apdu[4..5],
        },
        (6, Some(&0x00)) => return Err(Error::LcZero),
        // Extended length, no data
        (7, Some(&0x00)) => ApduRef {
            header: &apdu[..4],
            lc:     empty,
            data:   empty,
            le:     &apdu[4..],
        },
        // Extended length with data and maybe Le
        (_, Some(&0x00)) => {
            let lc = u16::from_be_bytes([apdu[4], apdu[5]]) as usize;
            if lc == 0 {
                return Err(Error::ExtendedLcZero);
            }
            if apdu.len() - 7 == lc {
                // Extended length with data and no Le
                ApduRef {
                    header: &apdu[..4],
                    lc:     &apdu[4..7],
                    data:   &apdu[7..],
                    le:     empty,
                }
            } else if apdu.len() - 9 == lc {
                // Extended length with data and Le
                ApduRef {
                    header: &apdu[..4],
                    lc:     &apdu[4..7],
                    data:   &apdu[7..7 + lc],
                    le:     &apdu[7 + lc..],
                }
            } else {
                return Err(Error::ExtendedApduTooLong);
            }
        }
        // Short with data and no Le
        (_, Some(&lc)) if apdu.len() - 5 == lc as usize => ApduRef {
            header: &apdu[..4],
            lc:     &apdu[4..5],
            data:   &apdu[5..],
            le:     empty,
        },
        // Short with data and Le
        (_, Some(&lc)) if apdu.len() - 6 == lc as usize => ApduRef {
            header: &apdu[..4],
            lc:     &apdu[4..5],
            data:   &apdu[5..apdu.len() - 1],
            le:     &apdu[apdu.len() - 1..],
        },
        _ => return Err(Error::ApduTooLong),
    })
}
