pub mod aes;
pub mod tdes;

use anyhow::Result;

pub const KDF_ENC: u32 = 1;
pub const KDF_MAC: u32 = 2;
pub const KDF_PACE: u32 = 3;

/// Cipher with encryption, decryption and MAC capabilities
pub trait Cipher: Sized {
    fn from_keys(kenc: &[u8], kmac: &[u8]) -> Result<Self>;
    fn block_size(&self) -> usize;
    fn enc(&self, data: &mut [u8], iv: &[u8]) -> Result<()>;
    fn dec(&self, data: &mut [u8], iv: &[u8]) -> Result<()>;
    fn mac(&self, data: &[u8]) -> Result<[u8; 8]>;
}

/// Cipher used in Secure Messaging
pub trait SMCipher: Cipher {
    fn from_seed(seed: &[u8]) -> Result<Self>;
    fn sm_enc(&self, ssc: u64, data: &mut [u8]) -> Result<()>;
    fn sm_dec(&self, ssc: u64, data: &mut [u8]) -> Result<()>;
}
