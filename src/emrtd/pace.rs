use {
    super::{secure_messaging::construct_secure_messaging, Emrtd},
    crate::{
        asn1::emrtd::security_info::{KeyAgreement, PaceInfo, PaceKeyMapping, SymmetricCipher},
        crypto::{
            cipher::{aes::*, tdes::*, Cipher, SMCipher},
            groups::ModPGroup,
            CryptoCoreRng,
        },
    },
    anyhow::{anyhow, bail, ensure, Result},
    der::{asn1::ObjectIdentifier as Oid, Encode, Length},
    sha1::{Digest, Sha1},
};

pub const KDF_PACE: u32 = 3;

use crate::crypto::{groups::EllipticCurve, KeyAgreementAlgorithm, PrivateKey, PublicKey};

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
        let (tag, mut nonce) = self
            .commands()
            .general_authenticate(&[], false)?
            .drain(..1)
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
        let (tag, map_card_pubkey) = self
            .commands()
            .general_authenticate(&[(0x81, &map_pubk.to_bytes())], false)?
            .drain(..1)
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(tag == 0x82);

        // b)
        let map_card_pubkey = map_kaa.parse_public_key(&map_card_pubkey)?;

        println!("mapping key");
        let eph_kaa = match info.protocol.key_mapping {
            PaceKeyMapping::Gm | PaceKeyMapping::Cam => {
                generic_mapping(&map_privk, &map_card_pubkey, &nonce)?
            }
            PaceKeyMapping::Im => todo!("INTEGRATED MAPPING"),
        };

        // c)
        println!("generating ephemeral keypair");
        let (eph_privk, eph_pubk) = eph_kaa.generate_key_pair(rng);
        let (tag, eph_card_pubk_ser) = self
            .commands()
            .general_authenticate(&[(0x83, &eph_pubk.to_bytes())], false)?
            .drain(..1)
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
        let (tag, rx_mac_pubk) = self
            .commands()
            .general_authenticate(&[(0x85, &mac_card_pubk)], true)?
            .drain(..1)
            .next()
            .ok_or_else(|| anyhow!("Expected data in GA response"))?;
        ensure!(tag == 0x86);

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
}
