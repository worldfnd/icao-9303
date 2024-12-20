//! 3DES cipher for Secure Messaging

use {
    super::{Cipher, KDF_ENC, KDF_MAC},
    cbc::{Decryptor as CbcDec, Encryptor as CbcEnc},
    cipher::{
        block_padding::NoPadding, BlockDecrypt as _, BlockDecryptMut as _, BlockEncrypt as _,
        BlockEncryptMut as _, InnerIvInit as _, KeyInit as _,
    },
    des::{Des, TdesEde2},
    sha1::{Digest, Sha1},
};

const BLOCK_SIZE: usize = 8;

pub struct TDesCipher {
    kenc: [u8; 16],
    kmac: [u8; 16],
}

impl Cipher for TDesCipher {
    fn from_seed(seed: &[u8]) -> Self {
        Self {
            kenc: kdf(seed, KDF_ENC),
            kmac: kdf(seed, KDF_MAC),
        }
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn enc(&self, _ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cipher = TdesEde2::new_from_slice(&self.kenc[..]).unwrap();
        let iv = [0; 8];
        let block_mode = CbcEnc::inner_iv_slice_init(cipher, &iv).unwrap();
        let len = data.len();
        block_mode
            .encrypt_padded_mut::<NoPadding>(data, len)
            .unwrap();
    }

    fn dec(&self, _ssc: u64, data: &mut [u8]) {
        assert!(data.len() % BLOCK_SIZE == 0);
        let cipher = TdesEde2::new_from_slice(&self.kenc[..]).unwrap();
        let iv = [0; 8];
        let block_mode = CbcDec::inner_iv_slice_init(cipher, &iv).unwrap();
        block_mode.decrypt_padded_mut::<NoPadding>(data).unwrap();
    }

    /// Retail MAC (ISO 9797-1 mode 3) using DES.
    // See <https://crypto.stackexchange.com/questions/18951/what-are-options-to-compute-des-retail-mac-aka-iso-9797-1-mode-3-under-pkcs11>
    fn mac(&self, _ssc: u64, data: &[u8]) -> [u8; 8] {
        assert_eq!(data.len() % BLOCK_SIZE, 0);
        let des1 = Des::new_from_slice(&self.kmac[..8]).unwrap();
        let des2 = Des::new_from_slice(&self.kmac[8..]).unwrap();
        let mut state = [0_u8; 8];
        for block in data.chunks_exact(8) {
            for i in 0..8 {
                state[i] ^= block[i];
            }
            des1.encrypt_block((&mut state).into());
        }
        des2.decrypt_block((&mut state).into());
        des1.encrypt_block((&mut state).into());
        state
    }
}

fn kdf(seed: &[u8], counter: u32) -> [u8; 16] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(counter.to_be_bytes());
    let hash = hasher.finalize();
    let mut key: [u8; 16] = hash[0..16].try_into().unwrap();
    set_parity_bits(&mut key);
    key
}

/// DES keys use only 7 bits per byte, with the least significant bit used for
/// parity.
fn set_parity_bits(key: &mut [u8]) {
    for byte in key {
        *byte &= 0xfe;
        *byte |= 1 ^ (byte.count_ones() as u8 & 1);
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{super::SecureMessaging, *},
        crate::emrtd::{pad, secure_messaging::Encrypted, seed_from_mrz},
        hex_literal::hex,
    };

    /// Example from ICAO 9303-11 section D.2
    #[test]
    fn test_bac_example() {
        let mrz = "L898902C<369080619406236";
        let seed = seed_from_mrz(mrz);
        assert_eq!(seed, hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        let (kenc, kmac) = (kdf(&seed, KDF_ENC), kdf(&seed, KDF_MAC));
        assert_eq!(kenc, hex!("AB94FDECF2674FDFB9B391F85D7F76F2"));
        assert_eq!(kmac, hex!("7962D9ECE03D1ACD4C76089DCE131543"));
    }

    // Example from ICAO 9303-11 section D.2
    #[test]
    fn test_derive_keys() {
        let k_seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let (kenc, kmac) = (kdf(&k_seed, KDF_ENC), kdf(&k_seed, KDF_MAC));
        assert_eq!(kenc, hex!("979EC13B1CBFE9DCD01AB0FED307EAE5"));
        assert_eq!(kmac, hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"));
    }

    #[test]
    fn test_mac_3des() {
        fn des_mac(key: &[u8; 16], msg: &[u8]) -> [u8; 8] {
            let cipher = TDesCipher {
                kenc: *key,
                kmac: *key,
            };
            let mut msg = msg.to_vec();
            pad(&mut msg, 8);
            cipher.mac(0, &msg)
        }

        let key = hex!("7962D9ECE03D1ACD4C76089DCE131543");
        let msg = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2").to_vec();
        let mac = hex!("5F1448EEA8AD90A7");
        assert_eq!(des_mac(&key, &msg), mac);

        let key = hex!("7962D9ECE03D1ACD4C76089DCE131543");
        let msg = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F").to_vec();
        let mac = hex!("2F2D235D074D7449");
        assert_eq!(des_mac(&key, &msg), mac);

        let key = hex!("F1CB1F1FB5ADF208806B89DC579DC1F8");
        let msg = hex!("887022120C06C2270CA4020C800000008709016375432908C044F6").to_vec();
        let mac = hex!("BF8B92D635FF24F8");
        assert_eq!(des_mac(&key, &msg), mac);
    }

    #[test]
    fn test_enc_3des() {
        fn des_enc(key: &[u8; 16], msg: &mut [u8]) {
            let cipher = TDesCipher {
                kenc: *key,
                kmac: *key,
            };
            cipher.enc(0, msg)
        }

        let key = hex!("AB94FDECF2674FDFB9B391F85D7F76F2");
        let msg = hex!("781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B");
        let enc = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
        let mut res = msg;
        des_enc(&key, &mut res[..]);
        assert_eq!(res, enc);

        let key = hex!("AB94FDECF2674FDFB9B391F85D7F76F2");
        let msg = hex!("4608F91988702212781723860C06C2260B4F80323EB3191CB04970CB4052790B");
        let enc = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        let mut res = msg;
        des_enc(&key, &mut res[..]);
        assert_eq!(res, enc);

        let key = hex!("979EC13B1CBFE9DCD01AB0FED307EAE5");
        let msg = hex!("011E800000000000");
        let enc = hex!("6375432908C044F6");
        let mut res = msg;
        des_enc(&key, &mut res[..]);
        assert_eq!(res, enc);
    }

    // Example from ICAO 9303-11 section D.4
    #[test]
    fn test_tdes_sm() {
        let seed = hex!("0036D272F5C350ACAC50C3F572D23600");
        let ssc = 0x887022120c06c226;
        let mut tdes = Encrypted::new(TDesCipher::from_seed(&seed[..]), ssc);

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
}
