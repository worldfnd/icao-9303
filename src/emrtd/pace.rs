use {
    super::{secure_messaging::construct_secure_messaging, Emrtd},
    crate::{
        asn1::emrtd::{
            security_info::{KeyAgreement, PaceInfo, PaceKeyMapping, SymmetricCipher},
            EfDg14,
        },
        crypto::{
            cipher::{aes::*, tdes::*, Cipher, SMCipher},
            groups::ModPGroup,
            mod_ring::UintExp,
            CryptoCoreRng,
        },
    },
    anyhow::{anyhow, bail, ensure, Result},
    der::{asn1::ObjectIdentifier as Oid, Encode, Length},
    num_traits::Inv,
    sha1::{Digest, Sha1},
};

pub const KDF_PACE: u32 = 3;

use crate::crypto::{groups::EllipticCurve, KeyAgreementAlgorithm, PrivateKey, PublicKey};

impl Emrtd {
    /// Perform PACE, establishing a secure messaging channel with the eMRTD.
    /// Returns `true` if the chip was proven authentic (not copied), `false`
    /// otherwise. In the latter case, performing Active or Chip
    /// Authentication is recommended.
    ///
    /// See ICAO-9303 11 4.4.
    pub fn pace(
        &mut self,
        rng: &mut impl CryptoCoreRng,
        mrz: &str,
        info: &PaceInfo,
    ) -> Result<bool> {
        // Derive symmetric key K_pi
        let k = k_from_mrz(mrz);
        let _k_pi = kdf_128(&k[..], KDF_PACE)?;

        // Send MSE:Set AT.
        let oid = Oid::from(info.protocol);
        let protocol = oid.as_bytes();
        self.commands().mset_at(0xc1a4, &[
            (0x80, protocol), // Cryptographic mechanism reference, PACE
            (0x83, &[0x01]),  // Reference of a key, MRZ
        ])?;
        println!("MSet AT OK");

        // ICAO 9303-11 4.4.1. Chained GENERAL AUTHENTICATE commands.
        // 1)
        let (tag, mut nonce) = self
            .commands()
            .general_authenticate(&[], false)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(tag == 0x80);
        println!("nonce {:?}", hex::encode(&nonce));

        // 2)
        decrypt_nonce(&mut nonce, mrz, &info)?;
        println!("decrypted nonce: {}", hex::encode(&nonce));

        // 3)
        // a)
        let map_kaa = info.kaa()?;
        let (map_privk, map_pubk) = map_kaa.generate_key_pair(rng);
        let (tag, map_card_pubkey_ser) = self
            .commands()
            .general_authenticate(&[(0x81, &map_pubk.to_bytes())], false)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(tag == 0x82);

        let map_card_pubkey = map_kaa.parse_public_key(&map_card_pubkey_ser)?;

        // b)
        println!("mapping key");
        let eph_kaa = match info.protocol.key_mapping {
            PaceKeyMapping::Gm | PaceKeyMapping::Cam => {
                generic_mapping(&map_privk, &map_card_pubkey, &nonce)?
            }
            PaceKeyMapping::Im => {
                // Request additional nonce
                let mut im_nonce = vec![0x00; nonce.len()];
                rng.fill_bytes(&mut im_nonce);
                let (tag, _) = self
                    .commands()
                    .general_authenticate(&[], false)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("Expected data in GA response"))?;
                ensure!(tag == 0x82);
                integrated_mapping(&map_card_pubkey, &nonce, &im_nonce)?
            }
        };

        // c)
        println!("generating ephemeral keypair");
        let (eph_privk, eph_pubk) = eph_kaa.generate_key_pair(rng);
        let (tag, eph_card_pubk_ser) = self
            .commands()
            .general_authenticate(&[(0x83, &eph_pubk.to_bytes())], false)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(tag == 0x84);
        println!("ephemeral card pubkey: {}", hex::encode(&eph_card_pubk_ser));

        let eph_card_pubk = eph_kaa.parse_public_key(&eph_card_pubk_ser)?;
        let k = eph_kaa.key_agreement(&eph_privk, &eph_card_pubk)?;
        println!("shared secret K: {}", hex::encode(&k));

        // d)
        ensure!(
            eph_card_pubk != eph_pubk,
            "eMRTD and own ephemeral public keys are the same"
        );

        // e), f)
        let mac_card_pubk = compute_auth_token(&k, &eph_card_pubk_ser, info)?;
        let mauth_resp = self
            .commands()
            .general_authenticate(&[(0x85, &mac_card_pubk)], true)?;
        let (tag, rx_mac_pubk) = mauth_resp
            .iter()
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(*tag == 0x86);

        let mac_pubk = compute_auth_token(&k, &eph_pubk.to_bytes(), info)?;
        ensure!(
            &rx_mac_pubk[..] == mac_pubk,
            "Received authentication code doesn't match own"
        );

        self.set_secure_messaging(construct_secure_messaging(
            info.protocol.cipher.unwrap(),
            &k,
            0,
        )?);

        if matches!(info.protocol.key_mapping, PaceKeyMapping::Cam) {
            let ef_dg14 = self.read_cached::<EfDg14>()?;
            let (_, pk) = ef_dg14
                .chip_authentication()
                .ok_or_else(|| anyhow!("Failed fetching Chip Authentication info from EF.DG14"))?;
            let ca_pubk = pk.public_key.to_algorithm_public_key()?.1;

            let (_, aic) = mauth_resp
                .iter()
                .skip(1)
                .find(|(tag, _)| *tag == 0x8a)
                .ok_or_else(|| {
                    anyhow!("Expected Encrypted Chip Authentication Data (0x8A) in GA response")
                })?;
            let caic = decrypt_aic(&aic, &k, &info)?;

            let private = map_kaa.parse_private_key(&caic)?;
            let public = map_kaa.parse_public_key(&ca_pubk.to_bytes())?;
            let recovered_map_pubk = map_kaa.key_agreement(&private, &public)?;

            // Use x of EC pubkey point
            let map_card_pubkey_ser = if let PublicKey::EC(_) = &public {
                let x_len = (map_card_pubkey_ser.len() - 1) / 2;
                &map_card_pubkey_ser[1..(x_len + 1)]
            } else {
                &map_card_pubkey_ser[..]
            };

            ensure!(recovered_map_pubk == map_card_pubkey_ser);

            return Ok(true);
        }

        Ok(false)
    }
}

pub fn k_from_mrz(mrz: &str) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(mrz.as_bytes());
    hasher.finalize().into()
}

fn decrypt_nonce(nonce: &mut [u8], mrz: &str, info: &PaceInfo) -> Result<()> {
    // Derive symmetric key K_pi
    let k = k_from_mrz(mrz);
    let k_pi = kdf_128(&k[..], KDF_PACE)?;
    match info.protocol.cipher.unwrap() {
        SymmetricCipher::Tdes => {
            let cipher = TDesCipher::from_keys(&k_pi, &[0; 16])?;
            cipher.dec(nonce, &[0; 8])?;
        }
        SymmetricCipher::Aes128 => {
            let cipher = Aes128Cipher::from_keys(&k_pi, &[0; 16])?;
            cipher.dec(nonce, &[0; 16])?;
        }
        SymmetricCipher::Aes192 => {
            let cipher = Aes192Cipher::from_keys(&k_pi, &[0; 16])?;
            cipher.dec(nonce, &[0; 16])?;
        }
        SymmetricCipher::Aes256 => {
            let cipher = Aes256Cipher::from_keys(&k_pi, &[0; 16])?;
            cipher.dec(nonce, &[0; 16])?;
        }
    };
    Ok(())
}

fn decrypt_aic(aic: &[u8], k: &[u8], info: &PaceInfo) -> Result<Vec<u8>> {
    let mut aic = aic.to_vec();
    let mut iv = vec![0xff; 16];
    match info.protocol.cipher.unwrap() {
        SymmetricCipher::Tdes => bail!("3DES not supported for Chip Authentication Mapping"),
        SymmetricCipher::Aes128 => {
            let cipher = Aes128Cipher::from_seed(&k).unwrap();
            cipher.enc(&mut iv, &[0; 16]).unwrap();
            cipher.dec(&mut aic, &iv).unwrap();
        }
        SymmetricCipher::Aes192 => {
            let cipher = Aes192Cipher::from_seed(&k).unwrap();
            cipher.enc(&mut iv, &[0; 16]).unwrap();
            cipher.dec(&mut aic, &iv).unwrap();
        }
        SymmetricCipher::Aes256 => {
            let cipher = Aes256Cipher::from_seed(&k).unwrap();
            cipher.enc(&mut iv, &[0; 16]).unwrap();
            cipher.dec(&mut aic, &iv).unwrap();
        }
    };
    // ISO/IEC 9797-1 Padding Method 2
    let len = aic.iter().rposition(|&x| x == 0x80).unwrap_or(aic.len());
    aic.truncate(len);

    Ok(aic)
}

/// Shared secret K, uncompressed public key, PACE info
fn compute_auth_token(shared_secret: &[u8], pubk: &[u8], info: &PaceInfo) -> Result<[u8; 8]> {
    let mut encodedpubk = Vec::new();
    let encoid = info.protocol.to_der()?;
    encodedpubk.extend_from_slice(&[0x7f, 0x49]);

    let pubk_len = Length::new(pubk.len().try_into()?);
    let total_len =
        Length::new((encoid.len() + 1 + pubk_len.to_der()?.len() + pubk.len()).try_into()?);
    encodedpubk.extend(total_len.to_der()?);

    // oid
    encodedpubk.extend(&encoid[..]);

    // key
    match info.protocol.key_agreement {
        KeyAgreement::Dh => encodedpubk.push(0x84),
        KeyAgreement::Ecdh => encodedpubk.push(0x86),
    }
    encodedpubk.extend(pubk_len.to_der()?);
    encodedpubk.extend_from_slice(&pubk);

    println!("encoded oid: {}", hex::encode(&encoid[..]));
    println!("encoded card pubk: {}", hex::encode(&encodedpubk));

    let mac = match info.protocol.cipher.unwrap() {
        SymmetricCipher::Tdes => {
            let cipher = TDesCipher::from_seed(&shared_secret)?;
            cipher.mac(&encodedpubk)?
        }
        SymmetricCipher::Aes128 => {
            let cipher = Aes128Cipher::from_seed(&shared_secret)?;
            cipher.mac(&encodedpubk)?
        }
        SymmetricCipher::Aes192 => {
            let cipher = Aes192Cipher::from_seed(&shared_secret)?;
            cipher.mac(&encodedpubk)?
        }
        SymmetricCipher::Aes256 => {
            let cipher = Aes256Cipher::from_seed(&shared_secret)?;
            cipher.mac(&encodedpubk)?
        }
    };

    Ok(mac)
}

type U521 = ruint::Uint<521, 9>;
use {
    crate::crypto::{key_agreement::ecka, mod_ring::RingRefExt},
    ruint::aliases::U4096,
};

fn generic_mapping(
    privk: &PrivateKey,
    pubk: &PublicKey,
    nonce: &[u8],
) -> Result<Box<dyn KeyAgreementAlgorithm>> {
    match pubk {
        PublicKey::DH(pubk) => {
            let private: &U4096 = privk
                .0
                .as_ref()
                .downcast_ref()
                .ok_or(anyhow!("Invalid private key"))?;
            let key = pubk.group.base_field().from(pubk.key);
            let h = key.pow_ct(*private);

            let g_hat = pubk.group.generator().pow_ct(U521::from_be_slice(nonce)) * h;

            let mapped_group = ModPGroup::new(
                pubk.group.base_field().modulus(),
                g_hat.to_uint(),
                pubk.group.scalar_field().modulus(),
            )?;

            Ok(Box::new(mapped_group))
        }
        PublicKey::EC(pubk) => {
            let map_private: &U521 = privk
                .0
                .as_ref()
                .downcast_ref()
                .ok_or_else(|| anyhow!("failed casting PrivateKey as Uint"))?;
            let map_private = pubk.curve.scalar_field().from_montgomery(*map_private);

            // potentially call .key_agreement() for h
            let (h_point, _) = ecka(map_private, pubk)?;
            let g_hat = pubk.curve.generator()
                * pubk.curve.scalar_field().from(U521::from_be_slice(nonce))
                + h_point;

            let (x, y) = g_hat
                .coordinates()
                .ok_or_else(|| anyhow!("failed getting g_hat coordinates"))?;

            let mapped_curve = EllipticCurve::new(
                pubk.curve.base_field().modulus(),
                pubk.curve.a().to_uint(),
                pubk.curve.b().to_uint(),
                x.to_uint(),
                y.to_uint(),
                pubk.curve.scalar_field().modulus(),
                pubk.curve.cofactor(),
            )?;

            Ok(Box::new(mapped_curve))
        }
        _ => bail!("unhandled key type"),
    }
}

use hex_literal::hex;
const C0_LENGTH_128: [u8; 16] = hex!("a668892a7c41e3ca739f40b057d85904");
const C1_LENGTH_128: [u8; 16] = hex!("a4e136ac725f738b01c1f60217c188ad");
const C0_LENGTH_256: [u8; 32] =
    hex!("d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676");
const C1_LENGTH_256: [u8; 32] =
    hex!("54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517");

fn pseudo_random(s: &[u8], t: &[u8], p: &U4096, cipher: SymmetricCipher) -> Result<Vec<u8>> {
    if s.is_empty() || t.is_empty() {
        bail!("Empty input");
    }

    let l = s.len() * 8; // length in bits
    let k = t.len() * 8; // key size in bits

    let (c0, c1) = match l {
        128 => (&C0_LENGTH_128[..], &C1_LENGTH_128[..]),
        192 | 256 => (&C0_LENGTH_256[..], &C1_LENGTH_256[..]),
        _ => bail!("Unknown length {}, expected 128, 192, or 256", l),
    };

    // First encryption to get the key
    let mut key = s.to_vec();
    match cipher {
        SymmetricCipher::Tdes => {
            let cipher = TDesCipher::from_keys(t, &[0; 16])?;
            cipher.enc(&mut key, &[0; 8])?
        }
        SymmetricCipher::Aes128 => {
            let cipher = Aes128Cipher::from_keys(t, &[0; 16])?;
            cipher.enc(&mut key, &[0; 16])?
        }
        SymmetricCipher::Aes192 => {
            let cipher = Aes192Cipher::from_keys(t, &[0; 16])?;
            cipher.enc(&mut key, &[0; 16])?
        }
        SymmetricCipher::Aes256 => {
            let cipher = Aes256Cipher::from_keys(t, &[0; 16])?;
            cipher.enc(&mut key, &[0; 16])?
        }
    };

    let mut x = Vec::new();
    let mut n = 0;

    // Continue encrypting until we have enough bits
    while n * l < p.significant_bits() as usize + 64 {
        let key_n = match cipher {
            SymmetricCipher::Tdes => {
                let cipher = TDesCipher::from_keys(&key[..k / 8], &[0; 16])?;
                let mut k = c0.to_vec();
                cipher.enc(&mut k, &[0; 8])?;
                let mut x_n = c1.to_vec();
                cipher.enc(&mut x_n, &[0; 8])?;
                x.extend_from_slice(&x_n);
                k
            }
            SymmetricCipher::Aes128 => {
                let cipher = Aes128Cipher::from_keys(&key[..k / 8], &[0; 16])?;
                let mut k = c0.to_vec();
                cipher.enc(&mut k, &[0; 16])?;
                let mut x_n = c1.to_vec();
                cipher.enc(&mut x_n, &[0; 16])?;
                x.extend_from_slice(&x_n);
                k
            }
            SymmetricCipher::Aes192 => {
                let cipher = Aes192Cipher::from_keys(&key[..k / 8], &[0; 16])?;
                let mut k = c0.to_vec();
                cipher.enc(&mut k, &[0; 16])?;
                let mut x_n = c1.to_vec();
                cipher.enc(&mut x_n, &[0; 16])?;
                x.extend_from_slice(&x_n);
                k
            }
            SymmetricCipher::Aes256 => {
                let cipher = Aes256Cipher::from_keys(&key[..k / 8], &[0; 16])?;
                let mut k = c0.to_vec();
                cipher.enc(&mut k, &[0; 16])?;
                let mut x_n = c1.to_vec();
                cipher.enc(&mut x_n, &[0; 16])?;
                x.extend_from_slice(&x_n);
                k
            }
        };
        key = key_n;
        n += 1;
    }

    let x_int = U4096::from_be_slice(&x);
    let result = x_int % p;

    use crate::crypto::{BsiTr031111Codec, Codec};
    let mut buf = Vec::new();
    let mut codec = BsiTr031111Codec::default();
    codec.uint_bytes = Some((p.significant_bits() + 7) / 8);
    codec.encode(&mut buf, result);
    Ok(buf)
}

fn integrated_mapping(
    pubk: &PublicKey,
    nonce: &[u8],
    im_nonce: &[u8],
) -> Result<Box<dyn KeyAgreementAlgorithm>> {
    match pubk {
        PublicKey::DH(pubk) => {
            let rp = pseudo_random(
                nonce,
                im_nonce,
                &U4096::from_be_slice(&pubk.group.base_field().modulus().to_be_bytes_vec()),
                SymmetricCipher::Aes128,
            )?;
            let g_hat = im_fg_dh(&rp, &pubk.group)?;

            let mapped_group = ModPGroup::new(
                pubk.group.base_field().modulus(),
                g_hat,
                pubk.group.scalar_field().modulus(),
            )?;

            Ok(Box::new(mapped_group))
        }
        PublicKey::EC(pubk) => {
            let rp = pseudo_random(
                nonce,
                im_nonce,
                &U4096::from_be_slice(&pubk.curve.base_field().modulus().to_be_bytes_vec()),
                SymmetricCipher::Aes128,
            )?;
            let (x, y) = im_fg_ecdh(&rp, &pubk.curve)?;

            let mapped_curve = EllipticCurve::new(
                pubk.curve.base_field().modulus(),
                pubk.curve.a().to_uint(),
                pubk.curve.b().to_uint(),
                x,
                y,
                pubk.curve.scalar_field().modulus(),
                pubk.curve.cofactor(),
            )?;
            Ok(Box::new(mapped_curve))
        }
        _ => bail!("unhandled key type"),
    }
}

fn im_fg_ecdh(t: &[u8], curve: &EllipticCurve<U521>) -> Result<(U521, U521)> {
    let p = curve.base_field().modulus();

    // Check if p ≡ 3 (mod 4)
    ensure!((p % U521::from(4)) == U521::from(3), "p != 3 (mod 4)");

    let t = U521::from_be_slice(t);
    let a = curve.a();
    let b = curve.b();
    let f = curve.cofactor();

    // 1. α = - t^2 mod p
    let alpha = -curve.base_field().from(t).pow_ct(U521::from(2));

    // 2. X_2 = -b a^-1 (1+(α+α^2)^-1) mod p, TODO consider Note
    let alpha_p_alpha2 = alpha + alpha.pow_ct(U521::from(2));
    let inner = alpha_p_alpha2.inv().unwrap() + curve.base_field().from(U521::from(1));
    let x_2 = -b * a.inv().unwrap() * inner;

    // 3. X_3 = αX_2 mod p
    let x_3 = alpha * x_2;

    // 4. h_2 = X_2^3 + aX_2 + b mod p
    let h_2 = x_2.pow_ct(U521::from(3)) + a * x_2 + b;

    // 5. h_3 not needed

    // 6. U = t^3 h_2 mod p
    let u = curve.base_field().from(t).pow_ct(U521::from(3)) * h_2;

    // 7. A = h_2^(p-1-(p+1)/4) mod p
    let power = p - U521::from(1) - (p + U521::from(1)) / U521::from(4);
    let a = h_2.pow_ct(power);

    // 8., 9. If A^2 h_2 = 1 mod p, use (X_2, A h_2), else use (X_3, AU)
    let (x, y) = if a.pow_ct(U521::from(2)) * h_2 == curve.base_field().from(U521::from(1)) {
        (x_2, a * h_2)
    } else {
        (x_3, a * u)
    };

    // 10. Multiply by cofactor if needed
    if f != U521::from(1) {
        let point = curve.from_affine(x, y)?;
        let scaled_point = point * curve.scalar_field().from(f);
        let (scaled_x, scaled_y) = scaled_point
            .coordinates()
            .ok_or_else(|| anyhow!("Invalid point after cofactor multiplication"))?;
        Ok((scaled_x.to_uint(), scaled_y.to_uint()))
    } else {
        Ok((x.to_uint(), y.to_uint()))
    }
}

fn im_fg_dh(x: &[u8], group: &ModPGroup<U4096, U4096>) -> Result<U4096> {
    let a = (group.base_field().modulus() - U4096::from(1)) / group.scalar_field().modulus();
    let y = group
        .base_field()
        .from(U4096::from_be_slice(x))
        .pow_ct(a)
        .to_uint();
    ensure!(y != U4096::from(1));
    Ok(y)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::crypto::{
            cipher::aes::kdf_128, ecdsa::ECPublicKey, BsiTr031111Codec, Codec,
            KeyAgreementAlgorithm, PublicKey,
        },
        der::Decode,
        hex_literal::hex,
        rand::thread_rng,
    };

    // ICAO 9303-11, Appendix G examples
    const MRZ: &str = "T22000129364081251010318";
    #[test]
    fn test_pace_example_g_mrz() {
        let k = k_from_mrz(MRZ);
        assert_eq!(k, hex!("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD"));
        let k_pi = kdf_128(&k[..], 3).unwrap();
        assert_eq!(k_pi, hex!("89DED1B2 6624EC1E 634C1989 302849DD"));
    }

    #[test]
    fn test_pace_example_g1() {
        let pace_info =
            PaceInfo::from_der(&hex!("3012060A 04007F00 07020204 02020201 0202010D")).unwrap();
        let kaa = pace_info.kaa().unwrap();
        // Get the curve
        let (_, curved) = kaa.generate_key_pair(&mut thread_rng());
        let curve = if let crate::crypto::PublicKey::EC(key) = curved {
            key.curve
        } else {
            panic!()
        };

        // Get nonce
        let mut nonce = hex!("95A3A016 522EE98D 01E76CB6 B98B42C3").to_vec();
        decrypt_nonce(&mut nonce, MRZ, &pace_info).unwrap();
        assert_eq!(nonce, hex!("3F00C4D3 9D153F2B 2A214A07 8D899B22"));

        // Generic mapping
        let map_i_privk = hex!(
            "7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C
             F21F249D 953BC46F 4C6E1925 9C010F99"
        );
        let map_i_pubk = hex!(
            "04
            7ACF3EFC 982EC455 65A4B155 129EFBC7 4650DCBF A6362D89 6FC70262 E0C2CC5E
            544552DC B6725218 799115B5 5C9BAA6D 9F6BC3A9 618E70C2 5AF71777 A9C4922D"
        );
        let map_c_privk = hex!(
            "498FF497 56F2DC15 87840041 839A8598
                                          2BE7761D 14715FB0 91EFA7BC E9058560"
        );
        let map_c_pubk = (
            hex!("824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57"),
            hex!("30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54"),
        );
        let h = (
            hex!("60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5"),
            hex!("0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181"),
        );
        let g_hat = (
            hex!("8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2"),
            hex!("8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522"),
        );

        // Check H (chip)
        let private = curve.scalar_field().from(U521::from_be_slice(&map_c_privk));
        let public = kaa.parse_public_key(&map_i_pubk).unwrap();
        let public = if let PublicKey::EC(key) = public {
            key
        } else {
            panic!()
        };
        let (_, serialized) = ecka(private, &public).unwrap();
        assert_eq!(serialized, h.0);

        // Check H (inspection)
        let private = curve.scalar_field().from(U521::from_be_slice(&map_i_privk));
        let public = ECPublicKey {
            curve: curve.clone(),
            point: (
                U521::from_be_slice(&map_c_pubk.0),
                U521::from_be_slice(&map_c_pubk.1),
            ),
        };
        let (h_point, serialized) = ecka(private, &public).unwrap();
        assert_eq!(serialized, h.0);

        // Check G^
        let g_hat_computed =
            curve.generator() * curve.scalar_field().from(U521::from_be_slice(&nonce)) + h_point;
        let mut serialized = Vec::new();
        BsiTr031111Codec::default().encode(&mut serialized, g_hat_computed.x().unwrap());
        assert_eq!(serialized, g_hat.0);

        // Check G^ with GM fn
        let kaa = generic_mapping(
            &PrivateKey(Box::new(private.as_montgomery())),
            &PublicKey::EC(public.clone()),
            &nonce,
        )
        .unwrap();
        let (_, po) = kaa.generate_key_pair(&mut thread_rng());
        let curve = if let PublicKey::EC(key) = po {
            key.curve
        } else {
            panic!()
        };
        assert_eq!(curve.generator().x().unwrap(), g_hat_computed.x().unwrap());
        println!("{:?}", U521::from_be_slice(&map_c_pubk.0));
        println!(
            "{:?}",
            curve.base_field().from(U521::from_be_slice(&map_c_pubk.0))
        );
        println!("{:?}", curve.base_field().modulus());
        curve.from_x(curve.base_field().from(U521::from_be_slice(&map_c_pubk.0)));

        // Check shared secret K
        let i_privk = hex!(
            "A73FB703 AC1436A1 8E0CFA5A BB3F7BEC
             7A070E7A 6788486B EE230C4A 22762595"
        );
        let i_pubk = (
            hex!("2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C"),
            hex!("3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462"),
        );
        let c_privk = hex!(
            "107CF586 96EF6155 053340FD 633392BA
                                      81909DF7 B9706F22 6F32086C 7AFF974A"
        );
        let c_pubk = (
            hex!("9E880F84 2905B8B3 181F7AF7 CAA9F0EF B743847F 44A306D2 D28C1D9E C65DF6DB"),
            hex!("7764B222 77A2EDDC 3C265A9F 018F9CB8 52E111B7 68B32690 4B59A019 3776F094"),
        );
        let k = hex!(
            "28768D20 701247DA E81804C9 E780EDE5
             82A9996D B4A31502 0B273319 7DB84925"
        );
        let kaa: Box<dyn KeyAgreementAlgorithm> = Box::new(curve.clone());
        // Check K (inspection)
        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&i_privk))
            .as_montgomery();
        let public = ECPublicKey {
            curve: curve.clone(),
            point: (
                U521::from_be_slice(&c_pubk.0),
                U521::from_be_slice(&c_pubk.1),
            ),
        };
        let serialized = kaa
            .key_agreement(
                &crate::crypto::PrivateKey(Box::new(private)),
                &PublicKey::EC(public),
            )
            .unwrap();
        assert_eq!(serialized, k);

        // Check K (chip)
        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&c_privk))
            .as_montgomery();
        let public = ECPublicKey {
            curve: curve.clone(),
            point: (
                U521::from_be_slice(&i_pubk.0),
                U521::from_be_slice(&i_pubk.1),
            ),
        };
        let serialized = kaa
            .key_agreement(
                &crate::crypto::PrivateKey(Box::new(private)),
                &PublicKey::EC(public.clone()),
            )
            .unwrap();
        assert_eq!(serialized, k);

        let cipher = Aes128Cipher::from_seed(&k).unwrap();

        // Mutual authentication
        let indata_tifd = hex!(
            "7F494F06 0A04007F 00070202 04020286
             41049E88 0F842905 B8B3181F 7AF7CAA9
             F0EFB743 847F44A3 06D2D28C 1D9EC65D
             F6DB7764 B22277A2 EDDC3C26 5A9F018F
             9CB852E1 11B768B3 26904B59 A0193776
             F094"
        );
        let tifd = cipher.mac(&indata_tifd).unwrap();
        assert_eq!(tifd, hex!("C2B0BD78 D94BA866"));

        let indata_tic = hex!(
            "7F494F06 0A04007F 00070202 04020286
             41042DB7 A64C0355 044EC9DF 190514C6
             25CBA2CE A4875488 7122F3A5 EF0D5EDD
             301C3556 F3B3B186 DF10B857 B58F6A7E
             B80F20BA 5DC7BE1D 43D9BF85 0149FBB3
             6462"
        );
        let tic = cipher.mac(&indata_tic).unwrap();
        assert_eq!(tic, hex!("3ABB9674 BCE93C08"));

        // Check above with token fn
        let mut buf = Vec::new();
        let mut codec = BsiTr031111Codec::default();
        codec.compressed_points = false;
        codec.encode(&mut buf, public.point().unwrap());
        let fn_tic = compute_auth_token(&k, &buf, &pace_info).unwrap();
        assert_eq!(fn_tic, hex!("3ABB9674 BCE93C08"));
    }

    #[test]
    fn test_pace_example_g2() {
        let pace_info =
            PaceInfo::from_der(&hex!("3012060A04007F00070202040102020102020100")).unwrap();
        let map_kaa = pace_info.kaa().unwrap();

        // Get nonce
        let mut nonce = hex!("854D8DF5 827FA685 2D1A4FA7 01CDDDCA").to_vec();
        decrypt_nonce(&mut nonce, MRZ, &pace_info).unwrap();
        assert_eq!(nonce, hex!("FA5B7E3E 49753A0D B9178B7B 9BD898C8"));

        // Generic mapping
        let map_i_privk = hex!("5265030F 751F4AD1 8B08AC56 5FC7AC95 2E41618D");
        let map_c_pubk = hex!(
            "78879F57 225AA808 0D52ED0F C890A4B2
             5336F699 AA89A2D3 A189654A F70729E6
             23EA5738 B26381E4 DA19E004 706FACE7
             B235C2DB F2F38748 312F3C98 C2DD4882
             A41947B3 24AA1259 AC22579D B93F7085
             655AF308 89DBB845 D9E6783F E42C9F24
             49400306 254C8AE8 EE9DD812 A804C0B6
             6E8CAFC1 4F84D825 8950A91B 44126EE6"
        );
        let h = hex!(
            "5BABEBEF 5B74E5BA 94B5C063 FDA15F1F
             1CDE9487 3EE0A5D3 A2FCAB49 F258D07F
             544F13CB 66658C3A FEE9E727 389BE3F6
             CBBBD321 28A8C21D D6EEA3CF 7091CDDF
             B08B8D00 7D40318D CCA4FFBF 51208790
             FB4BD111 E5A968ED 6B6F08B2 6CA87C41
             0B3CE0C3 10CE104E ABD16629 AA48620C
             1279270C B0750C0D 37C57FFF E302AE7F"
        );
        let g_hat = hex!(
            "7C9CBFE9 8F9FBDDA 8D143506 FA7D9306
             F4CB17E3 C71707AF F5E1C1A1 23702496
             84D64EE3 7AF44B8D BD9D45BF 6023919C
             BAA027AB 97ACC771 666C8E98 FF483301
             BFA4872D EDE9034E DFACB708 14166B7F
             36067682 9B826BEA 57291B5A D69FBC84
             EF1E7790 32A30580 3F743417 93E86974
             2D401325 B37EE856 5FFCDEE6 18342DC5"
        );

        // check H
        let group = crate::crypto::groups::named::modp_160_l();
        let public = map_kaa.parse_public_key(&map_c_pubk).unwrap();
        let private = group
            .scalar_field()
            .from(U4096::from_be_slice(&map_i_privk))
            .to_uint();

        let pubk = if let PublicKey::DH(key) = public.clone() {
            key
        } else {
            panic!()
        };

        let key = pubk.group.base_field().from(pubk.key);
        let h_computed = key.pow_ct(private);
        let mut h_serialized = Vec::new();
        BsiTr031111Codec::default().encode(&mut h_serialized, h_computed);
        assert_eq!(h_serialized, h);

        // check G^
        let g_hat_computed =
            pubk.group.generator().pow_ct(U521::from_be_slice(&nonce)) * h_computed;
        let mut g_hat_serialized = Vec::new();
        BsiTr031111Codec::default().encode(&mut g_hat_serialized, g_hat_computed);
        assert_eq!(g_hat_serialized, g_hat);

        let eph_kaa = generic_mapping(&PrivateKey(Box::new(private)), &public, &nonce).unwrap();

        let eph_i_privk = hex!("89CCD99B 0E8D3B1F 11E1296D CA68EC53 411CF2CA");
        let eph_c_pubk = hex!(
            "075693D9 AE941877 573E634B 6E644F8E
             60AF17A0 076B8B12 3D920107 4D36152B
             D8B3A213 F53820C4 2ADC79AB 5D0AEEC3
             AEFB9139 4DA476BD 97B9B14D 0A65C1FC
             71A0E019 CB08AF55 E1F72900 5FBA7E3F
             A5DC4189 9238A250 767A6D46 DB974064
             386CD456 743585F8 E5D90CC8 B4004B1F
             6D866C79 CE0584E4 9687FF61 BC29AEA1"
        );
        let k = hex!(
            "6BABC7B3 A72BCD7E A385E4C6 2DB2625B
             D8613B24 149E146A 629311C4 CA6698E3
             8B834B6A 9E9CD718 4BA8834A FF5043D4
             36950C4C 1E783236 7C10CB8C 314D40E5
             990B0DF7 013E64B4 549E2270 923D06F0
             8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E
             465E553E 77BDF75E 3193D383 4FC26E8E
             B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD"
        );

        // check K
        let public = eph_kaa.parse_public_key(&eph_c_pubk).unwrap();
        let private = group
            .scalar_field()
            .from(U4096::from_be_slice(&eph_i_privk))
            .to_uint();
        let k_computed = eph_kaa
            .key_agreement(&PrivateKey(Box::new(private)), &public)
            .unwrap();
        assert_eq!(k_computed, k);

        // check token (inspection)
        let computed_token = compute_auth_token(&k, &eph_c_pubk, &pace_info).unwrap();
        assert_eq!(computed_token, hex!("B46DD9BD 4D98381F"));
    }

    #[test]
    fn test_pace_example_h1() {
        let pace_info =
            PaceInfo::from_der(&hex!("3012060A 04007F00 07020204 04020201 0202010D")).unwrap();
        let map_kaa = pace_info.kaa().unwrap();

        // check nonce
        let k_pi = hex!("591468CD A83D6521 9CCCB856 0233600F");
        let mut nonce = hex!("143DC40C 08C8E891 FBED7DED B92B64AD");
        let cipher = Aes128Cipher::from_keys(&k_pi, &[0; 16]).unwrap();
        cipher.dec(&mut nonce, &[0; 16]).unwrap();
        assert_eq!(nonce, hex!("2923BE84 E16CD6AE 529049F1 F1BBE9EB"));

        let t = hex!("5DD4CBFC 96F5453B 130D890A 1CDBAE32");

        // check pseudo random function
        let curve = crate::crypto::groups::named::brainpool_p256r1_l();
        let rp = hex!(
            "A2F8FF2D F50E52C6 599F386A DCB595D2
             29F6A167 ADE2BE5F 2C3296AD D5B7430E"
        );

        let rp_computed = pseudo_random(
            &nonce,
            &t,
            &U4096::from_be_slice(&curve.base_field().modulus().to_be_bytes_vec()),
            SymmetricCipher::Aes128,
        )
        .unwrap();
        assert_eq!(rp_computed, rp);

        // check g_hat
        let g_hat = (
            hex!("8E82D315 59ED0FDE 92A4D049 8ADD3C23 BABA94FB 77691E31 E90AEA77 FB17D427"),
            hex!("4C1AE14B D0C3DBAC 0C871B7F 36081693 64437CA3 0AC243A0 89D3F266 C1E60FAD"),
        );

        let (x, y) = im_fg_ecdh(&rp, &curve).unwrap();
        let x_bytes = x.to_be_bytes_vec();
        let y_bytes = y.to_be_bytes_vec();
        assert_eq!(&x_bytes[x_bytes.len() - 32..], &g_hat.0);
        assert_eq!(&y_bytes[y_bytes.len() - 32..], &g_hat.1);

        let eph_i_privk = hex!(
            "A73FB703 AC1436A1 8E0CFA5A BB3F7BEC
             7A070E7A 6788486B EE230C4A 22762595"
        );
        let eph_c_pubk = hex!(
            "04
             67F78E5F 7F768608 2B293E8D 087E0569
             16D0F74B C01A5F89 57D0DE45 691E51E8
             932B69A9 62B52A09 85AD2C0A 271EE6A1
             3A8ADDDC D1A3A994 B9DED257 F4D22753"
        );
        let k = hex!(
            "4F150FDE 1D4F0E38 E95017B8 91BAE171
             33A0DF45 B0D3E18B 60BA7BEA FDC2C713"
        );

        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&eph_i_privk))
            .as_montgomery();
        let pubkey = map_kaa.parse_public_key(&eph_c_pubk).unwrap();
        let eph_kaa = integrated_mapping(&pubkey, &nonce, &t).unwrap();

        let computed_k = eph_kaa
            .key_agreement(&PrivateKey(Box::new(private)), &pubkey)
            .unwrap();
        assert_eq!(computed_k, k);

        let computed_token = compute_auth_token(&k, &eph_c_pubk, &pace_info).unwrap();
        assert_eq!(computed_token, hex!("450F02B8 6F6A0909"));
    }

    // DH 1060 IM
    #[test]
    fn test_pace_example_h2() {
        let pace_info =
            PaceInfo::from_der(&hex!("3012060A 04007F00 07020204 04020201 02020100")).unwrap();
        let map_kaa = pace_info.kaa().unwrap();

        // check nonce
        let k_pi = hex!("591468CD A83D6521 9CCCB856 0233600F");
        let mut nonce = hex!("9ABB8864 CA0FF155 1E620D1E F4E13510");
        let cipher = Aes128Cipher::from_keys(&k_pi, &[0; 16]).unwrap();
        cipher.dec(&mut nonce, &[0; 16]).unwrap();
        assert_eq!(nonce, hex!("FA5B7E3E 49753A0D B9178B7B 9BD898C8"));

        let t = hex!("B3A6DB3C 870C3E99 245E0D1C 06B747DE");

        // check pseudo random function
        let group = crate::crypto::groups::named::modp_160_l();
        let rp = hex!(
            "A0C7C50C 002061A5 1CC87D25 4EF38068
             607417B6 EE1B3647 3CFB800D 2D2E5FA2
             B6980F01 105D24FA B22ACD1B FA5C8A4C
             093ECDFA FE6D7125 D42A843E 33860383
             5CF19AFA FF75EFE2 1DC5F6AA 1F9AE46C
             25087E73 68166FB0 8C1E4627 AFED7D93
             570417B7 90FF7F74 7E57F432 B04E1236
             819E0DFE F5B6E77C A4999925 328182D2"
        );

        let rp_computed = pseudo_random(
            &nonce,
            &t,
            &U4096::from_be_slice(&group.base_field().modulus().to_be_bytes_vec()),
            SymmetricCipher::Aes128,
        )
        .unwrap();
        assert_eq!(rp_computed, rp);

        // check g_hat
        let g_hat = hex!(
            "1D7D767F 11E333BC D6DBAEF4 0E799E7A
             926B9697 3550656F F3C83072 6D118D61
             C276CDCC 61D475CF 03A98E0C 0E79CAEB
             A5BE2557 8BD4551D 0B109032 36F0B0F9
             76852FA7 8EEA14EA 0ACA87D1 E91F688F
             E0DFF897 BBE35A47 2621D343 564B262F
             34223AE8 FC59B664 BFEDFA2B FE7516CA
             5510A6BB B633D517 EC25D4E0 BBAA16C2"
        );

        let x = im_fg_dh(&rp, &group).unwrap();
        let x_bytes = x.to_be_bytes_vec();
        let from = U4096::BYTES - (x.significant_bits() + 7) / 8;
        assert_eq!(x_bytes[from..], g_hat);
    }

    #[test]
    fn test_pace_example_i1() {
        let pace_info =
            PaceInfo::from_der(&hex!("3012060A 04007F00 07020204 06020201 0202010D")).unwrap();
        let curve = crate::crypto::groups::named::brainpool_p256r1_l();
        let map_kaa = pace_info.kaa().unwrap();

        // check nonce
        let k_pi = hex!("4E6F6FBF 7BE748B9 32C7B741 61BBA9DF");
        let mut nonce = hex!("CB60E8E0 D85B76A9 BD304747 C2AD42E2");
        let cipher = Aes128Cipher::from_keys(&k_pi, &[0; 16]).unwrap();
        cipher.dec(&mut nonce, &[0; 16]).unwrap();
        assert_eq!(nonce, hex!("658B860B C94DF6F0 44FCE6D5 C82CF8E5"));

        // map nonce
        let map_i_privk =
            hex!("5D8BB87B D74D985A 4B7D4325 B9F7B976 FE835122 77340079 8914AA22 738135CC");
        let map_c_pubk = hex!(
            "04
             A234236A A9B9621E 8EFB73B5 245C0E09 D2576E52 77183C12 08BDD552 80CAE8B3
             04F36571 3A356E65 A451E165 ECC9AC0A C46E3771 342C8FE5 AEDD0926 85338E23"
        );

        let public = map_kaa.parse_public_key(&map_c_pubk).unwrap();
        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&map_i_privk))
            .as_montgomery();
        let eph_kaa = generic_mapping(&PrivateKey(Box::new(private)), &public, &nonce).unwrap();

        // perform key agreement
        let eph_i_privk =
            hex!("76ECFDAA 9841C323 A3F5FC5E 88B88DB3 EFF7E35E BF57A7E6 946CB630 006C2120");
        let eph_c_pubk = hex!(
            "04
             02AD566F 3C6EC7F9 324509AD 50A51FA5 2030782A 4968FCFE DF737DAE A9933331
             11C3B9B4 C2287789 BD137E7F 8AA882E2 A3C633CC D6ECC2C6 3C57AD40 1A09C2E1"
        );
        let k = hex!("67950559 D0C06B4D 4B86972D 14460837 461087F8 419FDBC3 6AAF6CEA AC462832");

        let public = eph_kaa.parse_public_key(&eph_c_pubk).unwrap();
        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&eph_i_privk))
            .as_montgomery();
        let k_computed = eph_kaa
            .key_agreement(&PrivateKey(Box::new(private)), &public)
            .unwrap();
        assert_eq!(k_computed, k);

        // mutual authentication
        let token_computed = compute_auth_token(&k, &eph_c_pubk, &pace_info).unwrap();
        assert_eq!(token_computed, hex!("E86BD060 18A1CD3B"));

        // chip auth
        let chip_auth_pubk_info = hex!(
            "30620609 04007F00 07020201 02305230
             0C060704 007F0007 01020201 0D034200
             04187270 9494399E 7470A643 1BE25E83
             EEE24FEA 568C2ED2 8DB48E05 DB3A610D
             C884D256 A40E35EF CB59BF67 53D3A489
             D28C7A4D 973C2DA1 38A6E7A4 A08F68E1
             6F02010D"
        );

        let mut c_auth_data = hex!(
            "1EEA964D AAE372AC 990E3EFD E6333353 BFC89A67 04D93DA8
             798CF77F 5B7A54BD 10CBA372 B42BE0B9 B5F28AA8 DE2F4F92"
        )
        .to_vec();
        let dec_c_auth_data = hex!(
            "85DC3FA9 3D0952BF A82F5FD1 89EE75BD
             82F11D1F 0B8ED4BF 5319AC9B 53C426B3"
        );
        let iv = hex!("F6A3B75A1 E933941 DD7A13E2 520779DF");
        let c_pubk_info = hex!(
            "04
             18727094 94399E74 70A6431B E25E83EE E24FEA56 8C2ED28D B48E05DB 3A610DC8
             84D256A4 0E35EFCB 59BF6753 D3A489D2 8C7A4D97 3C2DA138 A6E7A4A0 8F68E16F"
        );

        let cipher = Aes128Cipher::from_seed(&k).unwrap();
        let mut iv_computed = vec![0xff; 16];
        cipher.enc(&mut iv_computed, &[0; 16]).unwrap();
        assert_eq!(&iv_computed, &iv);

        cipher.dec(&mut c_auth_data, &iv).unwrap();
        // [ISO/IEC 9797-1] “Padding Method 2”.
        let len = c_auth_data
            .iter()
            .rposition(|&x| x == 0x80)
            .unwrap_or(c_auth_data.len());
        assert_eq!(c_auth_data[..len], dec_c_auth_data);

        let private = curve
            .scalar_field()
            .from(U521::from_be_slice(&dec_c_auth_data))
            .as_montgomery();
        let public = map_kaa.parse_public_key(&c_pubk_info).unwrap();
        let recovered_map_pubk = map_kaa
            .key_agreement(&PrivateKey(Box::new(private)), &public)
            .unwrap();
        let map_c_pubk_x = &map_c_pubk[1..33];
        assert_eq!(&recovered_map_pubk, &map_c_pubk_x);
    }
}
