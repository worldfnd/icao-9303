//! AES ciphers for Secure Messaging

use {
    super::{Cipher, KDF_ENC, KDF_MAC},
    aes::{Aes128, Aes192, Aes256},
    cbc::{Decryptor as CbcDec, Encryptor as CbcEnc},
    cipher::{
        block_padding::NoPadding, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
        KeyIvInit,
    },
    cmac::{Cmac, Mac},
    sha1::{Digest, Sha1},
    sha2::Sha256,
};

// All AES variantes have the same block size
const BLOCK_SIZE: usize = 16;

pub struct Aes128Cipher {
    kenc: [u8; 16],
    kmac: [u8; 16],
}

pub struct Aes192Cipher {
    kenc: [u8; 24],
    kmac: [u8; 24],
}

pub struct Aes256Cipher {
    kenc: [u8; 32],
    kmac: [u8; 32],
}

impl Aes128Cipher {
    fn iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes128::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Aes192Cipher {
    fn iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes192::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Aes256Cipher {
    fn iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes256::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Cipher for Aes128Cipher {
    fn from_seed(seed: &[u8]) -> Self {
        Self {
            kenc: kdf_128(seed, KDF_ENC),
            kmac: kdf_128(seed, KDF_MAC),
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcEnc::<Aes128>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .unwrap();
    }

    fn dec(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcDec::<Aes128>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.decrypt_padded_mut::<NoPadding>(data).unwrap();
    }

    fn mac(&self, _ssc: u64, data: &[u8]) -> [u8; 8] {
        assert!(data.len() % BLOCK_SIZE == 0);
        let mut cmac = <Cmac<Aes128> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        cmac.finalize().into_bytes()[0..8].try_into().unwrap()
    }
}

impl Cipher for Aes192Cipher {
    fn from_seed(seed: &[u8]) -> Self {
        Self {
            kenc: kdf_192(seed, KDF_ENC),
            kmac: kdf_192(seed, KDF_MAC),
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcEnc::<Aes192>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .unwrap();
    }

    fn dec(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcDec::<Aes192>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.decrypt_padded_mut::<NoPadding>(data).unwrap();
    }

    fn mac(&self, _ssc: u64, data: &[u8]) -> [u8; 8] {
        assert!(data.len() % BLOCK_SIZE == 0);
        let mut cmac = <Cmac<Aes192> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        cmac.finalize().into_bytes()[0..8].try_into().unwrap()
    }
}

impl Cipher for Aes256Cipher {
    fn from_seed(seed: &[u8]) -> Self {
        Self {
            kenc: kdf_256(seed, KDF_ENC),
            kmac: kdf_256(seed, KDF_MAC),
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcEnc::<Aes256>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .unwrap();
    }

    fn dec(&self, ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cbc = CbcDec::<Aes256>::new(&self.kenc.into(), &self.iv(ssc).into());
        cbc.decrypt_padded_mut::<NoPadding>(data).unwrap();
    }

    fn mac(&self, _ssc: u64, data: &[u8]) -> [u8; 8] {
        assert!(data.len() % BLOCK_SIZE == 0);
        let mut cmac = <Cmac<Aes256> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        cmac.finalize().into_bytes()[0..8].try_into().unwrap()
    }
}

/// Key Derivation Function (KDF) for 128-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_128(secret: &[u8], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    hash[0..16].try_into().unwrap()
}

/// Key Derivation Function (KDF) for 192-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_192(secret: &[u8], counter: u32) -> [u8; 24] {
    kdf_256(secret, counter)[0..24].try_into().unwrap()
}

/// Key Derivation Function (KDF) for 256-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_256(secret: &[u8], counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{Encrypted, SecureMessaging},
            *,
        },
        hex_literal::hex,
    };

    // Example ICAO 9303-11 section G.2
    #[test]
    fn test_derive_keys() {
        let shared_secret = hex!(
            "
                6BABC7B3 A72BCD7E A385E4C6 2DB2625B
                D8613B24 149E146A 629311C4 CA6698E3
                8B834B6A 9E9CD718 4BA8834A FF5043D4
                36950C4C 1E783236 7C10CB8C 314D40E5
                990B0DF7 013E64B4 549E2270 923D06F0
                8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E
                465E553E 77BDF75E 3193D383 4FC26E8E
                B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD
                "
        );
        let k_enc = hex!("2F7F46AD CC9E7E52 1B45D192 FAFA9126");
        let k_mac = hex!("805A1D27 D45A5116 F73C5446 9462B7D8");

        assert_eq!(kdf_128(&shared_secret, KDF_ENC), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC), k_mac);
    }

    // Example TR 03110 Worked Example 5
    #[test]
    fn test_derive_keys_2() {
        let shared_secret = hex!(
            "
            79 1D A0 42 73 CC FE 86 2E 52 DF 60 34 7E 25 57
            19 2E 1F 8D 75 17 82 2C E3 D3 06 05 6C 1C DE B4
            42 87 B3 07 2A 3E DC 60"
        );
        let k_enc = hex!("94 AB CD 27 1A B7 D9 A5 59 0B A5 2C B5 18 B8 31");
        let k_mac = hex!("78 B5 70 9E 7A BE DB 18 5B 42 4D 0E E3 A8 24 99 ");

        assert_eq!(kdf_128(&shared_secret, KDF_ENC), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC), k_mac);
    }

    // NIST SP 800-38B section D.1
    #[test]
    fn test_cmac_aes128() {
        let k = hex!("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        let msg = hex!(
            "6bc1bee2 2e409f96 e93d7e11 7393172a
            ae2d8a57 1e03ac9c 9eb76fac 45af8e51
            30c81c46 a35ce411 e5fbc119 1a0a52ef
            f69f2445 df4f9b17 ad2b417b e66c3710"
        );

        let cmac = |msg: &[u8]| {
            let mut cmac = <Cmac<Aes128> as KeyInit>::new(&k.into());
            cmac.update(msg);
            let result: [u8; 16] = cmac.finalize().into_bytes().into();
            result
        };

        assert_eq!(cmac(&msg[..0]), hex!("bb1d6929 e9593728 7fa37d12 9b756746"));
        assert_eq!(
            cmac(&msg[..16]),
            hex!("070a16b4 6b4d4144 f79bdd9d d04a287c")
        );
        assert_eq!(
            cmac(&msg[..40]),
            hex!("dfa66747 de9ae630 30ca3261 1497c827")
        );
        assert_eq!(
            cmac(&msg[..64]),
            hex!("51f0bebf 7e3b9d92 fc497417 79363cfe")
        );
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
