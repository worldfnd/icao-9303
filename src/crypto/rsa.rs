//! RSA signature verification implementation
//!
//! To *not* do: Signing. This will remain verifying only. RSA a minefield
//! of pitfalls and security issues and no-one should create new signatures
//! using it. See e.g. https://blog.trailofbits.com/2019/07/08/fuck-rsa

use {
    super::mod_ring::{ModRing, ModRingElementRef, RingRefExt, UintMont},
    crate::asn1::{
        public_key_info::SubjectPublicKeyInfo, signature_algorithm_identifier::RsaPssParameters,
        DigestAlgorithmIdentifier,
    },
    anyhow::{anyhow, bail, ensure, Error, Result},
    ruint::Uint,
    subtle::ConstantTimeEq,
};

#[derive(Clone, Debug)]
pub struct RSAPublicKey<U: UintMont> {
    ring:            ModRing<U>,
    public_exponent: U,
}

impl<U: UintMont> RSAPublicKey<U> {
    fn verify<'s>(
        &'s self,
        message: ModRingElementRef<'s, U>,
        signature: ModRingElementRef<'s, U>,
    ) -> Result<()> {
        assert_eq!(message.ring(), &self.ring);
        assert_eq!(signature.ring(), &self.ring);
        let expected = signature.pow_ct(self.public_exponent);
        ensure!(
            bool::from(message.ct_eq(&expected)),
            "Invalid RSA signature"
        );
        Ok(())
    }

    /// Verify a RSA-PSS signature, per RFC 8017.
    fn verify_pss(
        &self,
        message: &[u8],
        signature: &[u8],
        params: &RsaPssParameters,
    ) -> Result<()> {
        // Verifies h == h', where,
        // EM (expected message) = signature^e mod n
        // EM:  DB masked || h || 0xBC
        // DB (data block): padding |∣ 0x01 |∣ salt
        // DB masked = DB xor MFG(h)
        // h' = hash(padding || hash(message) || salt)

        let ring_bit_len = self.ring.modulus().bit_len();
        let digest_algo = &params.hash_algorithm;
        let salt_len = params.salt_length.as_bytes()[0] as usize;
        let trailer_field = params.trailer_field.as_bytes()[0] as usize;
        if trailer_field != 1 {
            bail!("Unrecognized trailer field {trailer_field}. Expected value 1 (= 0xbc)");
        }

        if signature.len() > ring_bit_len / 8 {
            bail!("Signature too large for {}-bit modulus", ring_bit_len);
        }
        let sig_uint = U::from_be_bytes(&signature);
        let ring_ref = &self.ring;
        let sig_elem = ring_ref.from(sig_uint);

        // Expected message: sig^e mod n
        let em_elem = sig_elem.pow_ct(self.public_exponent);
        let em_bytes = em_elem.to_uint().to_be_bytes();

        let em_len = (self.ring.modulus().bit_len() + 7) / 8;
        if em_bytes.len() > em_len {
            bail!("Calculated expected message longer than modulus");
        }

        // Check trailer (0xBC byte)
        if *em_bytes.last().unwrap_or(&0) != 0xbc {
            bail!("Invalid PSS trailer byte");
        }

        // Split DB/H from EM
        let hash_len = digest_algo.hash_bytes(&[]).len();
        if em_len < hash_len + salt_len + 2 {
            bail!("Encoded message too short for PSS");
        }
        let db_len = em_len - hash_len - 1;
        let db = &em_bytes[..db_len];
        let h = &em_bytes[db_len..db_len + hash_len];

        // MGF1 unmask
        let mgf_mask = mgf1(&digest_algo, h, db_len);
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
        if db_unmasked[..one_pos].iter().any(|&b| b != 0) {
            bail!("DB format mismatch: invalid padding");
        }

        // Recovered salt
        let salt = &db_unmasked[one_pos + 1..];

        if salt.len() != salt_len {
            bail!("Salt length mismatch");
        }

        // Compute h' = hash(padding || hash(message) || salt)
        let message_hash = digest_algo.hash_bytes(message);

        let mut pre_data = vec![0u8; 8]; // 8‐byte zero prefix
        pre_data.extend_from_slice(&message_hash);
        pre_data.extend_from_slice(salt);
        let h_prime = digest_algo.hash_bytes(&pre_data);

        if h_prime != h {
            bail!("PSS verification: hash check failed");
        }

        Ok(())
    }
}

fn mgf1(digest_alg: &DigestAlgorithmIdentifier, seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut mask = Vec::new();
    let mut counter: u32 = 0;
    while mask.len() < out_len {
        let mut data = Vec::with_capacity(seed.len() + 4);
        data.extend_from_slice(seed);
        data.extend_from_slice(&counter.to_be_bytes());
        let hash = digest_alg.hash_bytes(&data);
        mask.extend_from_slice(&hash);
        counter += 1;
    }

    mask.truncate(out_len);
    mask
}

impl<const B: usize, const L: usize> TryFrom<SubjectPublicKeyInfo> for RSAPublicKey<Uint<B, L>> {
    type Error = Error;

    fn try_from(info: SubjectPublicKeyInfo) -> Result<Self> {
        match info {
            SubjectPublicKeyInfo::Rsa(key) => {
                let modulus = Uint::<B, L>::try_from(key.modulus)?;
                Ok(Self {
                    ring:            ModRing::from_modulus(modulus),
                    public_exponent: Uint::<B, L>::try_from(key.public_exponent)?,
                })
            }
            _ => bail!("SubjectPublicKeyInfo is not RSA-variant"),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::asn1::{
            public_key_info::SubjectPublicKeyInfo,
            signature_algorithm_identifier::{MaskGenAlgorithm, RsaPssParameters},
            DigestAlgorithmIdentifier, DigestAlgorithmParameters,
        },
        anyhow::{ensure, Result},
        der::{asn1::Int, Decode},
        hex_literal::hex,
        num_traits::ToPrimitive,
        ruint::Uint,
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
            mask_gen_algorithm: MaskGenAlgorithm::Sha1(digest_algo),
            salt_length:        Int::new(&[32]).unwrap(),
            trailer_field:      Int::new(&[1]).unwrap(),
        };

        let pubkey_info = SubjectPublicKeyInfo::from_der(&subject_public_key)?;
        ensure!(matches!(pubkey_info, SubjectPublicKeyInfo::Rsa(_)));

        let pubkey = RSAPublicKey::<Uint<2048, 32>>::try_from(pubkey_info)?;
        assert_eq!(pubkey.public_exponent.to_u64().unwrap(), 65537);

        pubkey.verify_pss(&message, &signature, &params)?;

        Ok(())
    }
}
