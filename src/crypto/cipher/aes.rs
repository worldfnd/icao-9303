//! AES ciphers
//! Includes helpers for Secure Messaging

use {
    super::{Cipher, SMCipher, KDF_ENC, KDF_MAC},
    aes::{Aes128, Aes192, Aes256},
    anyhow::{anyhow, ensure, Result},
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
    pub kenc: [u8; 16],
    pub kmac: [u8; 16],
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
    fn sm_iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes128::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Aes192Cipher {
    fn sm_iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes192::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Aes256Cipher {
    fn sm_iv(&self, ssc: u64) -> [u8; BLOCK_SIZE] {
        let mut iv = [0; BLOCK_SIZE];
        iv[8..].copy_from_slice(ssc.to_be_bytes().as_ref());
        Aes256::new(&self.kenc.into()).encrypt_block((&mut iv).into());
        iv
    }
}

impl Cipher for Aes128Cipher {
    fn from_keys(kenc: &[u8], kmac: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kenc.try_into()?,
            kmac: kmac.try_into()?,
        })
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcEnc::<Aes128>::new(&self.kenc.into(), iv.try_into()?);
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn dec(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcDec::<Aes128>::new(&self.kenc.into(), iv.try_into()?);
        cbc.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn mac(&self, data: &[u8]) -> Result<[u8; 8]> {
        let mut cmac = <Cmac<Aes128> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        Ok(cmac.finalize().into_bytes()[0..8].try_into()?)
    }
}

impl SMCipher for Aes128Cipher {
    fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kdf_128(seed, KDF_ENC)?,
            kmac: kdf_128(seed, KDF_MAC)?,
        })
    }

    fn sm_enc(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.enc(data, &self.sm_iv(ssc))
    }

    fn sm_dec(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.dec(data, &self.sm_iv(ssc))
    }
}

impl Cipher for Aes192Cipher {
    fn from_keys(kenc: &[u8], kmac: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kenc.try_into()?,
            kmac: kmac.try_into()?,
        })
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcEnc::<Aes192>::new(&self.kenc.into(), iv.try_into()?);
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn dec(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcDec::<Aes192>::new(&self.kenc.into(), iv.try_into()?);
        cbc.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn mac(&self, data: &[u8]) -> Result<[u8; 8]> {
        let mut cmac = <Cmac<Aes192> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        Ok(cmac.finalize().into_bytes()[0..8].try_into()?)
    }
}

impl SMCipher for Aes192Cipher {
    fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kdf_192(seed, KDF_ENC)?,
            kmac: kdf_192(seed, KDF_MAC)?,
        })
    }

    fn sm_enc(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.enc(data, &self.sm_iv(ssc))
    }

    fn sm_dec(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.dec(data, &self.sm_iv(ssc))
    }
}

impl Cipher for Aes256Cipher {
    fn from_keys(kenc: &[u8], kmac: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kenc.try_into()?,
            kmac: kmac.try_into()?,
        })
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcEnc::<Aes256>::new(&self.kenc.into(), iv.try_into()?);
        cbc.encrypt_padded_mut::<NoPadding>(data, data.len())
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn dec(&self, data: &mut [u8], iv: &[u8]) -> Result<()> {
        ensure!(
            data.len() % BLOCK_SIZE == 0,
            "data length must be a multiple of block size (16)"
        );
        let cbc = CbcDec::<Aes256>::new(&self.kenc.into(), iv.try_into()?);
        cbc.decrypt_padded_mut::<NoPadding>(data)
            .map_err(|e| anyhow!("Encryption error: {:?}", e))?;
        Ok(())
    }

    fn mac(&self, data: &[u8]) -> Result<[u8; 8]> {
        let mut cmac = <Cmac<Aes256> as KeyInit>::new(&self.kmac.into());
        cmac.update(data);
        Ok(cmac.finalize().into_bytes()[0..8].try_into()?)
    }
}

impl SMCipher for Aes256Cipher {
    fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self {
            kenc: kdf_256(seed, KDF_ENC)?,
            kmac: kdf_256(seed, KDF_MAC)?,
        })
    }

    fn sm_enc(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.enc(data, &self.sm_iv(ssc))
    }

    fn sm_dec(&self, ssc: u64, data: &mut [u8]) -> Result<()> {
        self.dec(data, &self.sm_iv(ssc))
    }
}

/// Key Derivation Function (KDF) for 128-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_128(secret: &[u8], counter: u32) -> Result<[u8; 16]> {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    hash[0..16]
        .try_into()
        .map_err(|e| anyhow!("Failed converting slice: {e}"))
}

/// Key Derivation Function (KDF) for 192-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_192(secret: &[u8], counter: u32) -> Result<[u8; 24]> {
    Ok(kdf_256(secret, counter)?[0..24].try_into()?)
}

/// Key Derivation Function (KDF) for 256-bit AES keys.
/// ICAO 9303-11 section 9.7.1.2
pub fn kdf_256(secret: &[u8], counter: u32) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(counter.to_be_bytes());
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

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

        assert_eq!(kdf_128(&shared_secret, KDF_ENC).unwrap(), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC).unwrap(), k_mac);
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

        assert_eq!(kdf_128(&shared_secret, KDF_ENC).unwrap(), k_enc);
        assert_eq!(kdf_128(&shared_secret, KDF_MAC).unwrap(), k_mac);
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
}
