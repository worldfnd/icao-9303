//! RSA signature verification implementation
//!
//! To *not* do: Signing. This will remain verifying only. RSA a minefield
//! of pitfalls and security issues and no-one should create new signatures
//! using it. See e.g. https://blog.trailofbits.com/2019/07/08/fuck-rsa

use {
    super::mod_ring::{ModRing, ModRingElementRef, UintMont},
    crate::asn1::{
        public_key_info::{RsaPublicKeyInfo, SubjectPublicKeyInfo},
        signature_algorithm_identifier::{MaskGenAlgorithm, RsaPssParameters},
        DigestAlgorithmIdentifier, DigestAlgorithmParameters, SignatureAlgorithmIdentifier,
    },
    anyhow::{anyhow, bail, ensure, Error, Result},
    der::Encode,
    ruint::Uint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RSAPublicKey<U: UintMont> {
    pub ring:        ModRing<U>,
    public_exponent: U,
}

impl<U: UintMont> RSAPublicKey<U> {
    /// Verify an RSA signature.
    pub fn verify<'s>(
        &'s self,
        message: &[u8],
        signature: ModRingElementRef<'s, U>,
        algorithm: &'s SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        match algorithm {
            SignatureAlgorithmIdentifier::RsaPkcsSha1 => self.verify_pkcs1(
                message,
                signature,
                &DigestAlgorithmIdentifier::Sha1(DigestAlgorithmParameters::Null),
            ),
            SignatureAlgorithmIdentifier::RsaPkcsSha256 => self.verify_pkcs1(
                message,
                signature,
                &DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Null),
            ),
            SignatureAlgorithmIdentifier::RsaPkcsSha384 => self.verify_pkcs1(
                message,
                signature,
                &DigestAlgorithmIdentifier::Sha384(DigestAlgorithmParameters::Null),
            ),
            SignatureAlgorithmIdentifier::RsaPkcsSha512 => self.verify_pkcs1(
                message,
                signature,
                &DigestAlgorithmIdentifier::Sha512(DigestAlgorithmParameters::Null),
            ),
            SignatureAlgorithmIdentifier::RsaPss(params) => {
                self.verify_pss(message, signature, params)
            }
            _ => bail!("Unrecognized RSA signature algorithm"),
        }
    }

    /// Verify an RSA-PSS signature, per RFC 8017.
    fn verify_pss<'s>(
        &'s self,
        message: &[u8],
        signature: ModRingElementRef<'s, U>,
        params: &RsaPssParameters,
    ) -> Result<()> {
        // Verifies h == h', where,
        // EM (expected message) = signature^e mod n
        // EM:  DB masked || h || 0xBC
        // DB (data block): padding |∣ 0x01 |∣ salt
        // DB masked = DB xor MFG(h)
        // h' = hash(padding || hash(message) || salt)

        ensure!(signature.ring() == &self.ring);

        let ring_bit_len = self.ring.modulus().significant_bits();
        let digest_algo = &params.hash_algorithm;
        let salt_len = params.salt_length.as_bytes()[0] as usize;
        let trailer_field = params.trailer_field.as_bytes()[0] as usize;
        ensure!(
            trailer_field == 1,
            "Unrecognized trailer field {trailer_field}. Expected value 1 (= 0xbc)"
        );

        let em_elem = signature.pow_ct(self.public_exponent);
        let em_len = (ring_bit_len + 7) / 8;
        let mut em_bytes = em_elem.to_uint().to_be_bytes();
        if em_bytes.len() > em_len {
            em_bytes = em_bytes[em_bytes.len() - em_len..].to_vec();
        }

        // Check trailer (0xBC byte)
        ensure!(
            *em_bytes.last().unwrap_or(&0) == 0xbc,
            "Invalid PSS trailer byte"
        );

        // Split DB/H from EM
        let hash_len = digest_algo.hash_bytes(&[]).len();
        ensure!(
            em_len >= hash_len + salt_len + 2,
            "Encoded message too short for PSS"
        );

        let db_len = em_len - hash_len - 1;
        let db = &em_bytes[..db_len];
        let h = &em_bytes[db_len..db_len + hash_len];

        // MGF1 unmask
        let mgf_mask = match &params.mask_gen_algorithm {
            MaskGenAlgorithm::Mgf1(mgf1_da) => mgf1(mgf1_da, h, db_len),
            _ => bail!("Unrecognized MaskGenAlgorithm. Only MGF1 supported"),
        };
        let mut db_unmasked = vec![0u8; db_len];
        for (i, &b) in db.iter().enumerate() {
            db_unmasked[i] = b ^ mgf_mask[i];
        }
        let em_bits = ring_bit_len - 1;
        db_unmasked[0] &= 0xff >> (8 * em_len - em_bits);

        // Verify DB format
        let salt_start = db_len - salt_len;
        let mut one = None;
        for i in (0..salt_start).rev() {
            if db_unmasked[i] == 0x01 {
                one = Some(i);
                break;
            } else if db_unmasked[i] != 0x00 {
                break;
            }
        }
        let one_pos = one.ok_or_else(|| anyhow!("DB format mismatch: missing 0x01"))?;

        // Verify all bytes before 0x01 are 0x00
        ensure!(
            db_unmasked[..one_pos].iter().all(|&b| b == 0),
            "DB format mismatch: invalid padding"
        );

        // Recovered salt
        let salt = &db_unmasked[one_pos + 1..];
        ensure!(salt.len() == salt_len, "Salt length mismatch");

        // Compute h' = hash(padding || hash(message) || salt)
        let message_hash = params.hash_algorithm.hash_bytes(message);

        let mut pre_data = vec![0u8; 8]; // 8‐byte zero prefix
        pre_data.extend_from_slice(&message_hash);
        pre_data.extend_from_slice(salt);
        let h_prime = digest_algo.hash_bytes(&pre_data);

        ensure!(h_prime == h, "PSS verification: hash check failed");

        Ok(())
    }

    /// Verify an RSA-PKCS#1 v1.5 signature, per RFC 8017.
    fn verify_pkcs1<'s>(
        &'s self,
        message: &[u8],
        signature: ModRingElementRef<'s, U>,
        digest_algo: &DigestAlgorithmIdentifier,
    ) -> Result<()> {
        ensure!(signature.ring() == &self.ring);
        // Verifies t == t', where,
        // EM = 0x00 || 0x01 || PS || 0x00 || t
        // where PS is padding string of 0xff bytes
        // and t is DER encoding of DigestInfo = Seq { digestAlgo, digest }

        // Calculate EM = signature^e mod n
        let em_elem = signature.pow_ct(self.public_exponent);
        let em_len = (self.ring.modulus().significant_bits() + 7) / 8;
        let bytes = em_elem.to_uint().to_be_bytes();
        let em = bytes[bytes.len() - em_len..].to_vec();

        ensure!(em.len() >= 11, "Encoded message too short");
        ensure!(em[0] == 0x00 && em[1] == 0x01, "Invalid padding prefix");

        // Find T-prefixed 0x00 byte
        let mut sep_idx = None;
        for (i, &b) in em[2..].iter().enumerate() {
            if b == 0x00 {
                sep_idx = Some(i + 2);
                break;
            }
            ensure!(b == 0xff, "Invalid padding PS");
        }
        let sep_idx = sep_idx.ok_or_else(|| anyhow!("Missing padding PS-T separator"))?;
        let t_prime = &em[sep_idx + 1..];

        // Section 9.2 Note 1
        // Sequence initial encoding || DigestAlgo encoding
        let t_prefix = match digest_algo {
            DigestAlgorithmIdentifier::Sha1(_) => vec![
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            DigestAlgorithmIdentifier::Sha256(_) => vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            DigestAlgorithmIdentifier::Sha384(_) => vec![
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            DigestAlgorithmIdentifier::Sha512(_) => vec![
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            _ => bail!("Unsupported digest algorithm"),
        };

        // Input data
        let digest = digest_algo.hash_bytes(message);
        let mut t = Vec::with_capacity(t_prefix.len() + digest.len());
        t.extend_from_slice(&t_prefix);
        t.extend_from_slice(&digest);

        ensure!(t_prime == t, "RSA PKCS#1 verification: DigestInfo mismatch");

        Ok(())
    }
}

impl<const B: usize, const L: usize> TryFrom<RsaPublicKeyInfo> for RSAPublicKey<Uint<B, L>> {
    type Error = Error;

    fn try_from(info: RsaPublicKeyInfo) -> Result<Self> {
        let modulus = Uint::try_from(info.modulus)?;
        Ok(Self {
            ring:            ModRing::from_modulus(modulus),
            public_exponent: Uint::try_from(info.public_exponent)?,
        })
    }
}

fn mgf1(digest_algo: &DigestAlgorithmIdentifier, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut mask = Vec::new();
    let mut counter: u32 = 0;
    while mask.len() < out_len {
        let mut data = Vec::with_capacity(seed.len() + 4);
        data.extend_from_slice(seed);
        data.extend_from_slice(&counter.to_be_bytes());
        let hash = digest_algo.hash_bytes(&data);
        mask.extend_from_slice(&hash);
        counter += 1;
    }

    mask.truncate(out_len);
    mask
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            asn1::{
                public_key_info::SubjectPublicKeyInfo,
                signature_algorithm_identifier::{MaskGenAlgorithm, RsaPssParameters},
                DigestAlgorithmIdentifier, DigestAlgorithmParameters,
            },
            crypto::mod_ring::RingRefExt,
        },
        anyhow::Result,
        der::{asn1::Int, Decode},
        hex_literal::hex,
        num_traits::ToPrimitive,
        ruint::aliases::{U2048, U4096},
    };

    #[test]
    fn test_rsa_ssa_pss() -> Result<()> {
        // RSA-PSS example with MFG1/SHA256, 32 bytes salt
        let subject_public_key = hex!("30820122300d06092a864886f70d01010105000382010f003082010a0282010100a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d50203010001");
        let signature = hex!("68caf07e71ee654ffabf07d342fc4059deb4f7e5970746c423b1e8f668d5332275cc35eb61270aebd27855b1e80d59def47fe8882867fd33c2308c91976baa0b1df952caa78db4828ab81e79949bf145cbdfd1c4987ed036f81e8442081016f20fa4b587574884ca6f6045959ce3501ae7c02b1902ec1d241ef28dee356c0d30d28a950f1fbc683ee7d9aad26b048c13426fe3975d5638afeb5b9c1a99d162d3a5810e8b074d7a2eae2be52b577151f76e1f734b0a956ef4f22be64dc20a81ad1316e4f79dff5fc41fc08a20bc612283a88415d41595bfea66d59de7ac12e230f72244ad9905aef0ead3fa41ed70bf4218863d5f041292f2d14ce0a7271c6d36");
        let message = hex!("313233343030");
        // Construct RsaPssParamaters for this example
        let digest_algo = DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Absent);
        let params = RsaPssParameters {
            hash_algorithm:     digest_algo.clone(),
            mask_gen_algorithm: MaskGenAlgorithm::Mgf1(digest_algo.clone()),
            salt_length:        Int::new(&[32]).unwrap(),
            trailer_field:      Int::new(&[1]).unwrap(),
        };

        let pubkey_info = SubjectPublicKeyInfo::from_der(&subject_public_key)?;
        let pubkey = if let SubjectPublicKeyInfo::RSA(info) = pubkey_info {
            RSAPublicKey::<U2048>::try_from(info)?
        } else {
            bail!("SubjectPublicKeyInfo::RSA expected");
        };

        assert_eq!(pubkey.public_exponent.to_u64().unwrap(), 65537);

        let signature_uint = U2048::from_be_slice(&signature);
        let signature_elem = pubkey.ring.from(signature_uint);

        pubkey.verify_pss(&message, signature_elem, &params)?;

        Ok(())
    }

    #[test]
    fn test_rsa_ssa_pkcs1_1dot5() -> Result<()> {
        let signature_algo = hex!("300d06092a864886f70d01010b0500");
        let message = hex!("308202dfa003020102020101300d06092a864886f70d01010b0500303f310b3009060355040613024154310b3009060355040a13024756310c300a060355040b1303424d49311530130603550403130c435343412d41555354524941301e170d3036303630383232303030305a170d3231303931323231353935395a303f310b3009060355040613024154310b3009060355040a13024756310c300a060355040b1303424d49311530130603550403130c435343412d41555354524941308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c211f70191a4568fde7746707ac69f4ef8360e58999f649e6dbeddd0c7d42d418c92214b18b8c688942786228e62befd1840fa7b7ba01a18374aa7cbee6af466dcd24da93438df3aec31104d533e9a952c39e1647d54c55c508fb978c3a567745baa1006f0dccca2260b953657035b86c0d5a7db21bf37c205aca4ec9b8a422ad384f3c845064c0aef619d7a3786ec1d81505f1c223393de95bc0b43b892caa32cbf27255355fdfd7ebab16d8fffff15b2e51454d3c47048327188849b28612100b3a0bb2b954c1b179b3c36453a100d28eab9659309844943e9956147bc08608066027c1532832db3123a91d44d88fd33e6685a2203e7e943ae4a437cf064af41b28b4d2614bc0a3397d68a416889162cd7743fe9c6b6867eebe195de3c6b29626e98cc9c5661ae70a48de3587a188ebaf2f0d890970995600f000410b97e6cf7d15094f5629b3fa7eec5e477fd2896c13d5a8cfe08bb95dbbb21be8f601df712db18898a36407e4bc18531aa98814474a8400d89dfd4945ff315ed21f1ed09020300a9c3a37e307c301f0603551d23041830168014f97dc605cbe1836b1b707f4d5802953b017b7575301d0603551d0e04160414f97dc605cbe1836b1b707f4d5802953b017b7575300e0603551d0f0101ff04040302010630160603551d20040f300d300b06092a28000a010201010130120603551d130101ff040830060101ff020100");
        let signature = hex!("4bdaacac850d0c72d649ae861c2a87aeda4653d88071ba37998e9f373bf9cc98b0930ad3f159c467711d96c263707f4a3c91338dc2a5af49af4dad21db181be4c130c10abcb1068acef33c94ae8f5df765f77539553ce952de2d99abfb78feab88cd16db8521f86ca7fe123656bb0faf18773393f235f3cccb711fc2f16566c3327681414546621307d4a9907aec175a49254e47505c948d37e216aae17f9f24f1480a0e9762337f8e98e6d86f0b183345f9f673aa650b820913e6caa5d5dbf6eb43f231b3989005395ce151b4225f1949a209da2cff02a2c68913811a34a12e392e239e771c77ef4b8e38e72633ae24406b8cfc1f5d8abbab583b8a4a394f2f3bb3c0844635ba1eacd49b8061255eaf0a92dba2cb4acf077b7ffa65dbd190dda234075b92dffab429d9fb26fa3b65857d4e233f98f3a2aeadf6e6618735fb4cec0bf017f0395b3de8a6574a12ec33131e20b40a05183597bd284ccda9d09480f02467e9b38a33a21babb3d9cab02c56682ea4fc1af224dfcb02039b81131fc0");
        let subject_public_key = hex!("308201a2300d06092a864886f70d01010105000382018f003082018a0282018100c211f70191a4568fde7746707ac69f4ef8360e58999f649e6dbeddd0c7d42d418c92214b18b8c688942786228e62befd1840fa7b7ba01a18374aa7cbee6af466dcd24da93438df3aec31104d533e9a952c39e1647d54c55c508fb978c3a567745baa1006f0dccca2260b953657035b86c0d5a7db21bf37c205aca4ec9b8a422ad384f3c845064c0aef619d7a3786ec1d81505f1c223393de95bc0b43b892caa32cbf27255355fdfd7ebab16d8fffff15b2e51454d3c47048327188849b28612100b3a0bb2b954c1b179b3c36453a100d28eab9659309844943e9956147bc08608066027c1532832db3123a91d44d88fd33e6685a2203e7e943ae4a437cf064af41b28b4d2614bc0a3397d68a416889162cd7743fe9c6b6867eebe195de3c6b29626e98cc9c5661ae70a48de3587a188ebaf2f0d890970995600f000410b97e6cf7d15094f5629b3fa7eec5e477fd2896c13d5a8cfe08bb95dbbb21be8f601df712db18898a36407e4bc18531aa98814474a8400d89dfd4945ff315ed21f1ed09020300a9c3");

        let signature_algo = SignatureAlgorithmIdentifier::from_der(&signature_algo)?;
        let pubkey_info = SubjectPublicKeyInfo::from_der(&subject_public_key)?;
        let pubkey = if let SubjectPublicKeyInfo::RSA(info) = pubkey_info {
            RSAPublicKey::<U4096>::try_from(info)?
        } else {
            bail!("SubjectPublicKeyInfo::RSA expected");
        };

        assert_eq!(pubkey.public_exponent.to_u64().unwrap(), 43459);

        let signature_uint = U4096::from_be_slice(&signature);
        let signature_elem = pubkey.ring.from(signature_uint);

        let digest_algo = match signature_algo {
            SignatureAlgorithmIdentifier::RsaPkcsSha1 => {
                &DigestAlgorithmIdentifier::Sha1(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::RsaPkcsSha256 => {
                &DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::RsaPkcsSha384 => {
                &DigestAlgorithmIdentifier::Sha384(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::RsaPkcsSha512 => {
                &DigestAlgorithmIdentifier::Sha512(DigestAlgorithmParameters::Null)
            }
            _ => panic!(),
        };

        pubkey.verify_pkcs1(&message, signature_elem, &digest_algo)?;

        Ok(())
    }
}
