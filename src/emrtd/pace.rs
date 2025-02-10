use {
    super::{secure_messaging::construct_secure_messaging, Emrtd},
    crate::{
        asn1::emrtd::security_info::{PaceInfo, SymmetricCipher},
        crypto::{
            cipher::{aes::*, tdes::*, Cipher, SMCipher},
            CryptoCoreRng,
        },
    },
    anyhow::{ensure, Result},
    der::asn1::ObjectIdentifier as Oid,
    sha1::{Digest, Sha1},
};

pub const KDF_PACE: u32 = 3;

use crate::crypto::{
    groups::{EllipticCurve, EllipticCurvePoint},
    BsiTr031111Codec, Codec, PublicKey,
};

impl Emrtd {
    pub fn pace(&mut self, rng: &mut impl CryptoCoreRng, mrz: &str, info: &PaceInfo) -> Result<()> {
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
        let mut nonce = self.commands().general_authenticate(&[], false)?;
        nonce = decap_dyn(0x80, &nonce)?;
        println!("nonce {:?}", hex::encode(&nonce));

        // 2)
        decrypt_nonce(&mut nonce, mrz, &info)?;
        println!("decrypted nonce: {}", hex::encode(&nonce));

        // 3)
        // a)
        let kaa2 = {
            let map_kaa = info.kaa()?;
            let (map_privk, map_pubk) = map_kaa.generate_key_pair(rng);
            let map_card_pubkey = self
                .commands()
                .general_authenticate(&[(0x81, &map_pubk.to_bytes())], false)?;
            let map_card_pubkey = decap_dyn(0x82, &map_card_pubkey)?;
            let curve = crate::crypto::groups::named::brainpool_p256r1_l();

            // b)
            let map_ecpubk = publickey_to_ecpublickey(map_pubk);
            let map_private: &U521 = map_privk.0.as_ref().downcast_ref().unwrap();

            let map_card_ecpubkey = ecpubkeyser_to_ecpubkey(&map_card_pubkey, &curve);
            // let map_private = map_ecpubk.curve.scalar_field().from(*map_private);
            let map_private = curve.scalar_field().from_montgomery(*map_private);
            println!("running generic mapping");
            let kaa2 = generic_mapping_ecdh(map_private, &map_card_ecpubkey, &nonce);
            kaa2
        };

        // c)
        println!("generating ephemeral keypair");
        let curve = crate::crypto::groups::named::brainpool_p256r1_l();
        let (eph_privk, eph_pubk) = kaa2.generate_key_pair(rng);
        let eph_ecpubk = publickey_to_ecpublickey(eph_pubk.clone());
        let eph_card_pubk_ser = self
            .commands()
            .general_authenticate(&[(0x83, &eph_pubk.to_bytes())], false)?;
        let eph_card_pubk_ser = decap_dyn(0x84, &eph_card_pubk_ser)?;
        println!("ephemeral card pubkey: {}", hex::encode(&eph_card_pubk_ser));

        let eph_card_pubk = PublicKey::EC(ecpubkeyser_to_ecpubkey(&eph_card_pubk_ser, &curve));
        let k = kaa2.key_agreement(&eph_privk, &eph_card_pubk)?;
        println!("shared secret K: {}", hex::encode(&k));

        // d)
        ensure!(
            eph_card_pubk != eph_pubk,
            "eMRTD and own ephemeral public keys are the same"
        );

        // e), f)
        let mac_card_pubk = compute_auth_token(&k, &eph_card_pubk_ser, info)?;
        let rx_mac_pubk = self
            .commands()
            .general_authenticate(&[(0x85, &mac_card_pubk)], true)?;
        let rx_mac_pubk = decap_dyn(0x86, &rx_mac_pubk)?;

        let mac_pubk = compute_auth_token(&k, &eph_pubk.to_bytes(), info)?;
        ensure!(
            rx_mac_pubk == mac_pubk,
            "Received authentication code doesn't match own"
        );

        self.set_secure_messaging(construct_secure_messaging(
            info.protocol.cipher.unwrap(),
            &k,
            0,
        )?);

        Ok(())
    }
}

pub fn decap_dyn(tag: u8, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes[0] == 0x7c);
    ensure!(bytes[1] == bytes[2..].len() as u8);
    ensure!(bytes[2] == tag);
    ensure!(bytes[3] == bytes[4..].len() as u8);
    Ok(bytes[4..].to_vec())
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

/// Shared secret K, uncompressed public key, PACE info
fn compute_auth_token(shared_secret: &[u8], pubk: &[u8], info: &PaceInfo) -> Result<[u8; 8]> {
    let cipher = Aes128Cipher::from_seed(&shared_secret)?;

    let mut encodedpubk = Vec::new();
    use der::Encode;
    let encoid = info.protocol.to_der()?;
    encodedpubk.extend_from_slice(&[0x7f, 0x49]);
    encodedpubk.push((encoid[..].len() + 2 + pubk.len()) as u8);
    encodedpubk.extend_from_slice(&encoid[..]);
    encodedpubk.extend_from_slice(&[0x86, pubk.len() as u8]);
    encodedpubk.extend_from_slice(&pubk);

    println!("encoded oid: {}", hex::encode(&encoid[..]));
    println!("encoded card pubk: {}", hex::encode(&encodedpubk));

    Ok(cipher.mac(&encodedpubk)?)
}

fn publickey_to_ecpublickey(pk: PublicKey) -> ECPublicKey<U521> {
    if let PublicKey::EC(ecpubk) = pk {
        ecpubk
    } else {
        panic!()
    }
}

fn ecpubkeyser_to_ecpubkey(bytes: &[u8], curve: &EllipticCurve<U521>) -> ECPublicKey<U521> {
    let point: EllipticCurvePoint<'_, U521> = BsiTr031111Codec::default()
        .decode(&mut &bytes[..], curve)
        .unwrap();
    ECPublicKey {
        curve: curve.clone(),
        point: (point.x().unwrap().to_uint(), point.y().unwrap().to_uint()),
    }
}

type U521 = ruint::Uint<521, 9>;
use crate::crypto::{
    ecdsa::ECPublicKey,
    key_agreement::ecka,
    mod_ring::{ModRingElementRef, RingRefExt},
};

fn generic_mapping_ecdh<'a>(
    privk: ModRingElementRef<'a, U521>,
    pubk: &'a ECPublicKey<U521>,
    nonce: &[u8],
) -> Box<dyn crate::crypto::KeyAgreementAlgorithm> {
    // potentially call .key_agreement() for h
    let (h_point, _) = ecka(privk, pubk).unwrap();
    let g_hat = pubk.curve.generator() * pubk.curve.scalar_field().from(U521::from_be_slice(nonce))
        + h_point;

    let (x, y) = g_hat.coordinates().unwrap();

    let mapped_curve = EllipticCurve::new(
        pubk.curve.base_field().modulus(),
        pubk.curve.a().to_uint(),
        pubk.curve.b().to_uint(),
        x.to_uint(),
        y.to_uint(),
        pubk.curve.scalar_field().modulus(),
        pubk.curve.cofactor(),
    )
    .unwrap();

    Box::new(mapped_curve)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::crypto::{
            cipher::aes::kdf_128, BsiTr031111Codec, Codec, KeyAgreementAlgorithm, PublicKey,
        },
        der::Decode,
        hex_literal::hex,
        rand::thread_rng,
    };

    // ICAO 9303-11, Appendix G
    #[test]
    fn test_pace_example_g1() {
        let mrz = "T22000129364081251010318";
        let k = k_from_mrz(mrz);
        assert_eq!(k, hex!("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD"));
        let k_pi = kdf_128(&k[..], 3).unwrap();
        assert_eq!(k_pi, hex!("89DED1B2 6624EC1E 634C1989 302849DD"));

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
        decrypt_nonce(&mut nonce, mrz, &pace_info).unwrap();
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
        let public = ecpubkeyser_to_ecpubkey(&map_i_pubk, &curve);
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
        let kaa = generic_mapping_ecdh(private, &public, &nonce);
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
}
