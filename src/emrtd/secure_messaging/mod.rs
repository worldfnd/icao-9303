//! Secure Messaging

pub mod aes;
pub mod tdes;

use {
    self::{
        aes::{Aes128Cipher, Aes192Cipher, Aes256Cipher},
        tdes::TDesCipher,
    },
    super::{pad, Error, Result},
    crate::{
        asn1::emrtd::security_info::SymmetricCipher,
        ensure_err,
        iso7816::{parse_apdu, StatusWord},
    },
};

pub const KDF_ENC: u32 = 1;
pub const KDF_MAC: u32 = 2;

pub trait SecureMessaging {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>>;
}

pub trait Cipher {
    fn from_seed(seed: &[u8]) -> Self;
    fn block_size(&self) -> usize;
    fn enc(&self, ssc: u64, data: &mut [u8]);
    fn dec(&self, ssc: u64, data: &mut [u8]);
    fn mac(&self, ssc: u64, data: &[u8]) -> [u8; 8];
}

/// Secure Messaging protocol that passes APDUs and responses as-is.
#[derive(Debug, Default)]
pub struct PlainText;

pub struct Encrypted<C: Cipher> {
    cipher: C,
    ssc:    u64,
}

pub fn construct_secure_messaging(
    cipher: SymmetricCipher,
    seed: &[u8],
    ssc: u64,
) -> Box<dyn SecureMessaging> {
    match cipher {
        SymmetricCipher::Tdes => Box::new(Encrypted::new(TDesCipher::from_seed(seed), ssc)),
        SymmetricCipher::Aes128 => Box::new(Encrypted::new(Aes128Cipher::from_seed(seed), ssc)),
        SymmetricCipher::Aes192 => Box::new(Encrypted::new(Aes192Cipher::from_seed(seed), ssc)),
        SymmetricCipher::Aes256 => Box::new(Encrypted::new(Aes256Cipher::from_seed(seed), ssc)),
    }
}

impl SecureMessaging for PlainText {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        Ok(apdu.to_vec())
    }

    fn dec_response(&mut self, _status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        Ok(resp.to_vec())
    }
}

impl<C: Cipher> Encrypted<C> {
    pub fn new(cipher: C, ssc: u64) -> Self {
        Self { cipher, ssc }
    }
}

impl<C: Cipher> SecureMessaging for Encrypted<C> {
    fn enc_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        // Increment send sequence counter
        let ssc = self.ssc.wrapping_add(1);

        // Parse APDU
        let apdu = parse_apdu(apdu)?;
        let ins_even = apdu.ins() & 1 == 0;
        let extended_length = apdu.is_extended_length();

        // Write header
        let mut papdu = apdu.header.to_vec();
        papdu[0] |= 0x0c; // Set SM bit

        // Placeholder for data length
        papdu.extend_from_slice(if extended_length {
            &[0x00, 0x00, 0x00]
        } else {
            &[0x00]
        });

        // Write encrypted data
        if !apdu.data.is_empty() {
            let mut payload = apdu.data.to_vec();
            pad(&mut payload, self.cipher.block_size());
            self.cipher.enc(ssc, &mut payload);
            papdu.push(if ins_even { 0x87 } else { 0x85 });
            papdu.push((payload.len() + 1) as u8);
            papdu.push(0x01); // Tag for 80 00* padding
            papdu.extend_from_slice(&payload);
        }

        // Write Le
        if !apdu.le.is_empty() {
            papdu.push(0x97);
            papdu.push(apdu.le.len() as u8);
            papdu.extend_from_slice(apdu.le);
        }

        // Write MAC (mandatory)
        {
            // Prepare MAC input
            let mut message = vec![0; self.cipher.block_size() - 8];
            message.extend_from_slice(&ssc.to_be_bytes());
            message.extend_from_slice(&papdu[..4]);
            pad(&mut message, self.cipher.block_size());
            if extended_length {
                message.extend_from_slice(&papdu[7..]);
            } else {
                message.extend_from_slice(&papdu[5..]);
            }
            pad(&mut message, self.cipher.block_size());

            // Compute MAC and append to papdu
            let mac = self.cipher.mac(ssc, &message);
            papdu.push(0x8e);
            papdu.push(mac.len() as u8);
            papdu.extend_from_slice(&mac);
        }

        // Patch data length
        if extended_length {
            let len = papdu.len() - 7;
            papdu[5] = (len >> 8) as u8;
            papdu[6] = (len & 0xff) as u8;
        } else {
            papdu[4] = (papdu.len() - 5) as u8;
        }

        // Write Le
        if extended_length {
            papdu.extend_from_slice(&[0x00, 0x00]);
        } else {
            papdu.extend_from_slice(&[0x00]);
        };

        // Commit SSC
        self.ssc = ssc;
        Ok(papdu)
    }

    fn dec_response(&mut self, status: StatusWord, resp: &[u8]) -> Result<Vec<u8>> {
        ensure_err!(resp.len() >= 14, Error::SMResponseInvalid);

        // Split off DO'8E object containing MAC
        let (resp, mac) = resp.split_at(resp.len() - 10);
        ensure_err!(mac[0] == 0x8e, Error::SMResponseInvalid);
        ensure_err!(mac[1] == 0x08, Error::SMResponseInvalid);
        let mac = &mac[2..];

        // Compute and verify MAC
        self.ssc = self.ssc.wrapping_add(1);
        let mut n = vec![0; self.cipher.block_size() - 8];
        n.extend_from_slice(&self.ssc.to_be_bytes());
        n.extend_from_slice(resp);
        pad(&mut n, self.cipher.block_size());
        let mac2 = self.cipher.mac(self.ssc, &n);
        ensure_err!(mac == mac2, Error::SMResponseMacFailed);

        // Split off DO'99 object and check (redundant) status word.
        // TODO: DO'99 is optional, so we should check if it's present.
        // TODO: DO'99 is allowed to be empty.
        let (resp, do99) = resp.split_at(resp.len() - 4);
        ensure_err!(do99[0] == 0x99, Error::SMResponseInvalid);
        ensure_err!(do99[1] == 0x02, Error::SMResponseInvalid);
        ensure_err!(do99[2] == status.sw1(), Error::SMResponseInvalid);
        ensure_err!(do99[3] == status.sw2(), Error::SMResponseInvalid);

        // If no data remaining there was no response data
        if resp.is_empty() {
            return Ok(Vec::new());
        }

        // Decrypt DO'87 response data object
        // TODO: Allow for trailing data.
        ensure_err!(resp.len() >= 11, Error::SMResponseInvalid);
        ensure_err!(resp[0] == 0x85 || resp[0] == 0x87, Error::SMResponseInvalid);
        // Parse BER-TLV length
        let (tl_len, length) = match resp[1] {
            0x00..=0x7f => (2, resp[1] as usize),
            0x81 => (3, resp[2] as usize),
            0x82 => (4, u16::from_be_bytes([resp[2], resp[3]]) as usize),
            0x83 => (
                5,
                u32::from_be_bytes([0, resp[2], resp[3], resp[4]]) as usize,
            ),
            0x84 => (
                6,
                u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize,
            ),
            _ => {
                return Err(Error::SMResponseInvalid);
            }
        };
        let resp = &resp[tl_len..];
        ensure_err!(resp.len() == length, Error::SMResponseInvalid);
        ensure_err!(resp[0] == 0x01, Error::SMResponseInvalid);
        let mut resp = resp[1..].to_vec();
        ensure_err!(
            resp.len() % self.cipher.block_size() == 0,
            Error::SMResponseInvalid
        );
        self.cipher.dec(self.ssc, &mut resp);
        let length = resp
            .iter()
            .rposition(|&x| x == 0x80)
            .ok_or(Error::SMResponseInvalid)?; // Unpadding failed
        resp.truncate(length);

        Ok(resp)
    }
}

impl<C: Cipher + 'static> From<C> for Box<dyn SecureMessaging> {
    fn from(cipher: C) -> Self {
        Box::new(Encrypted::new(cipher, 0))
    }
}
