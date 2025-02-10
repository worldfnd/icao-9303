//! Secure Messaging

use {
    super::{pad, Error, Result},
    crate::{
        asn1::emrtd::security_info::SymmetricCipher,
        crypto::cipher::{
            aes::{Aes128Cipher, Aes192Cipher, Aes256Cipher},
            tdes::TDesCipher,
            SMCipher,
        },
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

/// Secure Messaging protocol that passes APDUs and responses as-is.
#[derive(Debug, Default)]
pub struct PlainText;

pub struct Encrypted<C: SMCipher> {
    cipher: C,
    ssc:    u64,
}

pub fn construct_secure_messaging(
    cipher: SymmetricCipher,
    seed: &[u8],
    ssc: u64,
) -> Result<Box<dyn SecureMessaging>> {
    match cipher {
        SymmetricCipher::Tdes => Ok(Box::new(Encrypted::new(
            TDesCipher::from_seed(seed).map_err(Error::SMError)?,
            ssc,
        ))),
        SymmetricCipher::Aes128 => Ok(Box::new(Encrypted::new(
            Aes128Cipher::from_seed(seed).map_err(Error::SMError)?,
            ssc,
        ))),
        SymmetricCipher::Aes192 => Ok(Box::new(Encrypted::new(
            Aes192Cipher::from_seed(seed).map_err(Error::SMError)?,
            ssc,
        ))),
        SymmetricCipher::Aes256 => Ok(Box::new(Encrypted::new(
            Aes256Cipher::from_seed(seed).map_err(Error::SMError)?,
            ssc,
        ))),
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

impl<C: SMCipher> Encrypted<C> {
    pub fn new(cipher: C, ssc: u64) -> Self {
        Self { cipher, ssc }
    }
}

impl<C: SMCipher> SecureMessaging for Encrypted<C> {
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
            self.cipher
                .sm_enc(ssc, &mut payload)
                .map_err(|_| Error::SMResponseInvalid)?;
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
            let mac = self
                .cipher
                .mac(&message)
                .map_err(|_| Error::SMResponseMacFailed)?;
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
        let mac2 = self
            .cipher
            .mac(&n)
            .map_err(|_| Error::SMResponseMacFailed)?;
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
        self.cipher
            .sm_dec(self.ssc, &mut resp)
            .map_err(|_| Error::SMResponseInvalid)?;
        let length = resp
            .iter()
            .rposition(|&x| x == 0x80)
            .ok_or(Error::SMResponseInvalid)?; // Unpadding failed
        resp.truncate(length);

        Ok(resp)
    }
}

impl<C: SMCipher + 'static> From<C> for Box<dyn SecureMessaging> {
    fn from(cipher: C) -> Self {
        Box::new(Encrypted::new(cipher, 0))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // Example from ICAO 9303-11 section D.4
    #[test]
    fn test_tdes_sm() {
        let seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let ssc = 0x887022120c06c226;
        let mut tdes = Encrypted::new(TDesCipher::from_seed(&seed[..]).unwrap(), ssc);

        // Select EF.COM
        let apdu = hex!("00 A4 02 0C 02 01 1E");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(
            papdu,
            hex!("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
        );
        let rapdu = hex!("990290008E08FA855A5D4C50A8ED");
        let dec = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(dec, hex!(""));

        // Read Binary of first four bytes
        let apdu = hex!("00 B0 00 00 04");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000000D9701048E08ED6705417E96BA5500"));
        let rapdu = hex!("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED");
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("60145F01"));

        // Read Binary of remaining 18 bytes from offset 4
        let apdu = hex!("00 B0 00 04 12");
        let papdu = tdes.enc_apdu(&apdu).unwrap();
        assert_eq!(papdu, hex!("0CB000040D9701128E082EA28A70F3C7B53500"));
        let rapdu = hex!(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D74"
        );
        let data = tdes.dec_response(0x9000.into(), &rapdu).unwrap();
        assert_eq!(data, hex!("04303130365F36063034303030305C026175"));
    }

    // Example TR 03110 Worked Example 8
    #[test]
    fn test_aes128_enc() {
        let kenc = hex!("2F 7F 46 AD CC 9E 7E 52 1B 45 D1 92 FA FA 91 26");
        let kmac = hex!("80 5A 1D 27 D4 5A 51 16 F7 3C 54 46 94 62 B7 D8");

        let cipher = Aes128Cipher { kenc, kmac };
        let mut sm = Encrypted::new(cipher, 0);

        // 8.1
        let apdu = hex!("00 22 81 B6 11 83 0F 44 45 54 45 53 54 43 56 43 41 30 30 30 30 33");
        let papdu = hex!(
            "0C 22 81 B6 2D 87 21 01 B3 7B B5 7D A1 DB 37 D1 C4 96 04 91 7B D6 99 E6 1D 6A 30 74 \
             E6 9E 40 67 A1 B3 99 03 88 23 36 33 8E 08 F3 65 26 DE 03 A3 1A 19 00"
        );
        let result = sm.enc_apdu(&apdu).unwrap();
        eprintln!("RES: {}", hex::encode(&result));
        eprintln!("COR: {}", hex::encode(&papdu));
        assert_eq!(result, papdu);

        let _crapdu = hex!("99 02 90 00 8E 08 EB FF 08 D3 B2 0A 04 14");
        let _rapdu = hex!("90 00");
        // let result = sm.dec_response(&crapdu).unwrap();
        // assert_eq!(result, rapdu);

        // 8.2

        // 8.3
        let _apdu = hex!("00 22 81 B6 0F 83 0D 44 45 54 45 53 54 44 56 44 45 30 31 39");
        let _capdu = hex!(
            "
            0C 22 81 B6 1D 87 11 01 6A B8 1B 7D 96 08 24 93
            AF 87 D2 C4 2F B2 8C 85 8E 08 DE CB F7 59 13 BC
            1A 76 00"
        );
        let _crapdu = hex!("99 02 90 00 8E 08 C5 29 A8 ED 4B DC B9 96");
        let _rapdu = hex!("90 00");

        // 8.4
        let _apdu = hex!(
            "
            00 2A 00 BE 00 01 6A 7F 4E 81 E2 5F 29 01 00 42
            0D 44 45 54 45 53 54 44 56 44 45 30 31 39 7F 49
            81 94 06 0A 04 00 7F 00 07 02 02 02 01 01 81 81
            80 9F 7E F6 8E 15 3D B4 FD 10 84 DD ED BE AE 84
            2C 55 6D 41 9F CB 5E F6 21 AA 37 51 F0 FC 0C FD
            71 4F C0 E7 68 86 6B 3F 44 E2 72 5A F0 35 1A 97
            ED B1 BA 88 DF DD 9B 4D 81 D4 08 FE 07 63 34 6A
            77 2C F6 46 16 46 5C 8F D9 71 B7 75 D2 E1 34 26
            C5 BC 11 89 47 95 C5 AD 2C 3E 42 68 37 F3 A1 01
            9F E9 51 24 EA 5D 43 3E 90 6D 79 93 49 63 21 EF
            CB DB C3 2D 93 C0 68 0B 45 F3 B8 F6 4A 5D AF CF
            B9 82 03 01 00 01 5F 20 0D 44 45 54 45 53 54 41
            54 44 45 30 31 39 7F 4C 12 06 09 04 00 7F 00 07
            03 01 02 02 53 05 00 00 00 01 10 5F 25 06 01 00
            00 03 02 04 5F 24 06 01 00 00 04 02 04 5F 37 81
            80 8C B1 61 26 A1 FD BB 82 48 C8 8B DB 1F B1 19
            9C 3F 25 38 56 FE 10 83 5F 7B FF 62 A3 0B D2 81
            B8 A1 F0 FE 03 81 A5 B0 A4 26 51 F7 7D F7 21 52
            21 F0 ED E4 88 E6 89 EA 45 CE E2 0B 19 C7 B1 D1
            ED B6 AC 21 F3 40 88 81 9F 6F D5 DC 33 31 09 E1
            5A 15 DF F6 85 A2 B6 9D 17 D5 E2 3D AF E3 63 A8
            E7 63 31 CC 25 B9 13 FB 6E D8 30 EB 45 7A D0 A6
            73 96 A1 90 CA E3 9C C6 C2 E4 67 1E 60 52 D3 C2
            2D
        "
        );
        let _capdu = hex!(
            "
            0C 2A 00 BE 00 01 7F 87 82 01 71 01 16 52 C1 F3
            1A 4C E5 A7 E6 A5 B7 9D D4 18 E7 27 DA 11 6A FA
            3F 23 A7 7D 6C 9B 45 FB BD 1B FC E3 94 0B A5 D4
            41 E4 50 A2 32 C8 85 B4 42 18 90 50 3E B6 AB E5
            4A EC B7 F8 A0 33 E2 D7 65 8B 83 AD 7A F5 A4 E6
            A6 44 BE A1 A0 CE 8D 3D 4D E4 34 F2 E3 58 91 24
            BB 1C 3A F1 1C D1 8D 3F 32 75 A5 71 C9 61 AD 57
            ED 6F D6 F6 3E BD A9 95 E1 38 31 E6 4B 3C 09 63
            7F 5C 22 57 D1 AC 0D 7D D7 87 0D BD 65 44 70 52
            AC 90 50 2C 60 01 C0 75 69 F1 3C 5B CF D7 09 72
            E7 A4 F8 19 4D 43 51 D0 4E 94 AF 0C 0B 14 5B 8C
            AE 62 9E FC 4D 7E 92 48 89 A1 9E 6A 01 1F DA 27
            CE AA ED 7E 2E E6 4C 96 53 E4 92 1C EE 4C 2E EB
            45 C3 59 90 50 CC 5D 57 1D 6C 90 E0 65 FD 34 DC
            6D 9E A6 83 08 E1 7E D2 1F 4C E8 DB 24 D8 15 59
            3F 73 39 B2 61 18 6B 75 98 9C 5B F2 C6 78 9D 1F
            B6 AA 4B BB FA 3F D2 31 84 ED B8 2A 86 77 34 5C
            4B C3 B8 F6 2F BE 91 1E 5D 0D 47 0E 06 16 17 31
            14 88 6C 92 31 6D D7 65 92 1C 67 EC 94 30 DD 55
            50 A8 D0 EC 22 5E 2E 36 64 39 E4 24 E2 5D E0 F4
            9A 9B 9C 00 79 2F AE EF EA 32 56 51 70 64 BC E4
            6C 23 44 05 B0 A6 52 E0 DD 09 A5 16 31 A7 B6 12
            05 61 5A F5 7A A3 42 5F C6 87 4A AB D4 E1 9B 2E
            2E A2 21 BB 30 96 AF 66 86 28 C4 81 8E 08 EF 7E
            FA 58 DA 6E D9 DD 00 00"
        );
        let _cracpdu = hex!("99 02 90 00 8E 08 B9 87 F8 19 0C DE 76 4D ");
        let _rapdu = hex!("90 00");

        // 8.5

        // 8.6

        // 8.7
    }
}
