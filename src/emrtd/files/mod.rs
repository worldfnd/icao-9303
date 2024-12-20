mod file_id;

pub use self::file_id::{DedicatedId, FileId};
use {
    super::{Emrtd, Error, Result},
    crate::{
        asn1::emrtd::{EfCardAccess, EfDg14, EfSod},
        ensure_err,
        iso7816::StatusWord,
    },
    der::{Decode, ErrorKind, Reader, SliceReader},
    std::collections::HashMap,
};

pub type FileCache = HashMap<FileId, Option<Vec<u8>>>;

pub trait HasFileId {
    const FILE_ID: FileId;
}

impl HasFileId for EfSod {
    const FILE_ID: FileId = FileId::Sod;
}

impl HasFileId for EfCardAccess {
    const FILE_ID: FileId = FileId::CardAccess;
}

impl HasFileId for EfDg14 {
    const FILE_ID: FileId = FileId::Dg14;
}

impl Emrtd {
    pub fn read_cached<T: HasFileId + for<'a> Decode<'a>>(&mut self) -> Result<T> {
        let der = self
            .read_file_cached(T::FILE_ID)?
            .ok_or(Error::FileNotFound)?;
        Ok(T::from_der(der.as_slice())?)
    }

    /// Retrieves a file with caching.
    ///
    /// Assumes the file is a single TLV structure.
    ///
    /// Returns Ok(None) if the file is not found.
    pub fn read_file_cached(&mut self, file: FileId) -> Result<Option<Vec<u8>>> {
        // Try cache first.
        if let Some(entry) = self.file_cache.get(&file) {
            return Ok(entry.clone());
        }

        // Select parent file if necessary.
        if self.parent != file.parent() {
            if let Some(application_id) = file.parent().aid() {
                self.select_dedicated_file(application_id)?;
            } else {
                self.select_master_file()?;
            }
        }

        // Read file by short EF.
        let mut result: Option<Vec<u8>> = match self.read_binary_short_ef(file.short_id()) {
            Ok(data) => Some(data),
            Err(Error::ErrorResponse(StatusWord::FILE_NOT_FOUND)) => None,
            Err(e) => return Err(e),
        };
        if let Some(result) = result.as_mut() {
            loop {
                // Check if we are done by parsing the header.
                if sniff_len(result)? <= Some(result.len()) {
                    break;
                }
                let chunk = self.read_binary_offset(result.len())?;
                if chunk.is_empty() {
                    break;
                }
                result.extend(&chunk);
            }

            // Some (e.g. Polish) passports will zero-extend the file on READ BINARY OFFSET
            // commands. Trim the file to the actual length.
            let expected_len = sniff_len(result)?.ok_or(Error::ResponseDataUnexpected)?;
            ensure_err!(result.len() >= expected_len, Error::ResponseDataUnexpected);
            result.truncate(expected_len);
        }

        // Insert in cache
        self.file_cache.insert(file, result.clone());
        Ok(result)
    }

    pub fn select_master_file(&mut self) -> Result<()> {
        // Select by file identifier
        // See ISO/IEC 7816-4 section 11.2.2
        let (status, data) = self.send_apdu(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])?;
        ensure_err!(status.is_success(), status.into());
        self.parent = DedicatedId::MasterFile;
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
        Ok(())
    }

    pub fn select_dedicated_file(&mut self, application_id: &[u8]) -> Result<()> {
        if application_id.len() > 16 {
            return Err(Error::InvalidApplicationId);
        }
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x0C, application_id.len() as u8];
        apdu.extend_from_slice(application_id);
        let (status, data) = self.send_apdu(&apdu)?;
        ensure_err!(status.is_success(), status.into());
        self.parent = DedicatedId::from_aid(application_id);
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
        Ok(())
    }

    pub fn select_elementary_file(&mut self, file: u16) -> Result<()> {
        // Select by elementary file by file identifier.
        // Not the application DF has to be previously selected.
        // See ISO/IEC 7816-4 section 11.2.2
        // See ICAO 9303-10 section 3.6.2
        let file_bytes = file.to_be_bytes();
        let (status, data) =
            self.send_apdu(&[0x00, 0xA4, 0x02, 0x0C, 0x02, file_bytes[0], file_bytes[1]])?;
        ensure_err!(status.is_success(), status.into());
        ensure_err!(data.is_empty(), Error::ResponseDataUnexpected);
        Ok(())
    }

    /// Read binary data from an elementary file using a Short EF identifier.
    ///
    /// This is the recommended way to read data from an elementary file.
    ///
    /// See ICAO 9303-10 section 3.6.3.2 and ISO 7816-4 section 11.3.3.
    // TODO: Check for extended length support before using.
    // See ICAO 9303-10 section 3.6.4.2.
    pub fn read_binary_short_ef(&mut self, file: u8) -> Result<Vec<u8>> {
        if file > 0x1F {
            return Err(Error::InvalidShortFileId);
        }
        // Note b8 of p2 must be set to 1 to indicate that a short file id is used.
        // Setting P2 to 0 means 'offset zero'.
        // Setting Le to 0x00 means read up to 256 / 65536.
        let apdu = if self.extended_length {
            // Setting Le to 0x000000 means 'read all' with extended length.
            &[0x00, 0xB0, 0x80 | file, 0x00, 0x00, 0x00, 0x00][..]
        } else {
            // Setting Le to 0x00 means 'read all'.
            &[0x00, 0xB0, 0x80 | file, 0x00, 0x00][..]
        };
        let (status, data) = self.send_apdu(apdu)?;
        ensure_err!(status.is_success(), status.into());
        Ok(data)
    }

    /// Reads the current file at a given offset.
    pub fn read_binary_offset(&mut self, offset: usize) -> Result<Vec<u8>> {
        // TODO: use B1 for large offsets.
        ensure_err!(offset < (1 << 15), Error::ResponseTooLong);
        let offset = (offset as u16).to_be_bytes();

        // Setting Le to 0x00 means 'read all'.
        // See ISO 7816-4 section 11.3.3.
        // NOTE: Polish passports will zero-pad the response to 256 bytes, going beyond EOF.
        let (status, data) = self.send_apdu(&[0x00, 0xB0, offset[0], offset[1], 0x00])?;
        ensure_err!(status.is_success(), status.into());
        Ok(data)
    }
}

/// Sniff the size of a TLV encoded data structure.
fn sniff_len(bytes: &[u8]) -> Result<Option<usize>> {
    // Check if we are done by parsing the header.
    match SliceReader::new(bytes)?.peek_header() {
        Ok(header) => {
            let total_len: u32 = header.length.for_tlv()?.into();
            Ok(Some(total_len as usize))
        }
        Err(e) => {
            if let ErrorKind::Incomplete { .. } = e.kind() {
                Ok(None)
            } else {
                Err(e.into())
            }
        }
    }
}
