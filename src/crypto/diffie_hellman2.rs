//! Diffie-Hellman key exchange on Mod P groups.

use {
    super::{
        mod_ring::{ModRing, ModRingElementRef, RingRefExt},
        CryptoCoreRng, KeyAgreementAlgorithm, PrivateKey, PublicKey,
    },
    crate::asn1::public_key::{DhAlgoParameters, PubkeyAlgorithmIdentifier, SubjectPublicKeyInfo},
    anyhow::{anyhow, bail, ensure, Result},
    der::{asn1::BitString, Decode},
    rand::{CryptoRng, Rng, RngCore},
    std::fmt::{Debug, Display},
};

// The largest prime field we support is 4096 bits.
// This covers all named MODP groups.
// https://www.rfc-editor.org/rfc/rfc5114
pub type Uint = ruint::Uint<2048, 32>;
pub type PrimeField = ModRing<Uint>;
pub type PrimeFieldElement<'a> = ModRingElementRef<'a, Uint>;

impl PrimeField {
    // Generate a value 1 < x < p−1 (See PKCS #3).
    // Note: Montgomery form does not affect the normal distribution.
    pub fn random_pkcs_3(&self, mut rng: impl CryptoRng + RngCore) -> PrimeFieldElement {
        let lower = Uint::from(1);
        let upper = self.modulus() - Uint::from(1);
        loop {
            let mut value = rng.gen::<Uint>();
            // Zero out the high bits.
            for b in self.modulus().bit_len()..Uint::BITS {
                value.set_bit(b, false);
            }
            if value > lower && value < upper {
                return self.from(value);
            }
        }
    }
}

impl PrimeFieldElement<'_> {
    pub fn field(&self) -> &PrimeField {
        self.ring()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModPGroup {
    base_field: PrimeField,
    generator_monty: Uint,
    private_value_length: Option<usize>,
}

impl ModPGroup {
    pub fn from_algorithm(algo: &PubkeyAlgorithmIdentifier) -> Result<Self> {
        match algo {
            PubkeyAlgorithmIdentifier::Dh(params) => Self::from_parameters(params),
            _ => bail!("Unsupported algorithm for diffie-hellman"),
        }
    }

    pub fn from_parameters(params: &DhAlgoParameters) -> Result<Self> {
        let modulus: Uint = (&params.prime).try_into()?;
        let generator: Uint = (&params.base).try_into()?;
        ensure!(generator < modulus, "Generator must be less than modulus");
        let private_value_length = params
            .private_value_length
            .map(|l| l.try_into())
            .transpose()?;
        if let Some(l) = private_value_length {
            ensure!(modulus.bit_len() > l, "Private value length too large.");
        }
        let field = PrimeField::from_modulus(modulus);
        let generator = field.from(generator);
        // Unfortunately the parameters do not provide the order of the generator.
        // So we can not construct the scalar field.
        Ok(Self {
            base_field: field,
            generator_monty: generator.as_montgomery(),
            private_value_length,
        })
    }

    pub fn from_generator(
        generator: PrimeFieldElement<'_>,
        private_value_length: Option<usize>,
    ) -> Self {
        Self {
            base_field: *generator.field(),
            generator_monty: generator.as_montgomery(),
            private_value_length,
        }
    }

    pub fn base_field(&self) -> &PrimeField {
        &self.base_field
    }

    pub fn generator(&self) -> PrimeFieldElement<'_> {
        self.base_field.from_montgomery(self.generator_monty)
    }

    pub fn el_from_bitstring(&self, bits: &BitString) -> Result<PrimeFieldElement<'_>> {
        let uint = Uint::from_der(bits.raw_bytes())?;
        ensure!(uint < self.base_field.modulus());
        Ok(self.base_field.from(uint))
    }

    pub fn el_from_monty(&self, el: Uint) -> PrimeFieldElement<'_> {
        self.base_field.from(el)
    }

    // Convert to octet string according to PKCS#3
    pub fn el_to_octet_string(&self, el: PrimeFieldElement) -> Vec<u8> {
        assert_eq!(el.field(), self.base_field());
        let bytes = el.to_uint().to_be_bytes::<256>();
        let k = 256 - self.base_field.modulus().byte_len();
        assert!(bytes[0..k].iter().all(|b| *b == 0x00));
        bytes[k..].to_vec()
    }

    pub fn el_to_bytes(&self, el: PrimeFieldElement) -> Vec<u8> {
        assert_eq!(el.field(), self.base_field());
        el.to_uint().to_be_bytes_trimmed_vec()
    }

    // Convert from octet string according to PKCS#3
    pub fn el_from_bytes(&self, bytes: &[u8]) -> Result<PrimeFieldElement<'_>> {
        let uint = Uint::from_be_slice(bytes);
        ensure!(uint < self.base_field.modulus());
        Ok(self.base_field.from(uint))
    }

    pub fn private_to_public_key(&self, private_key: Uint) -> PrimeFieldElement<'_> {
        self.generator().pow_ct(private_key)
    }

    /// Generate private key according to PKCS #3.
    pub fn generate_private_key(&self, mut rng: impl CryptoRng + RngCore) -> Uint {
        if let Some(bits) = self.private_value_length {
            // Generate a value 2^(bits - 1) < 2^bits
            // TODO: X9.42 (repro in RFC 2631) require [2, (q - 2)]
            let mut value = rng.gen::<Uint>();
            for b in bits..Uint::BITS {
                value.set_bit(b, false);
            }
            value.set_bit(bits - 1, true);
            assert!(value >= Uint::from(2).pow(Uint::from(bits - 1)));
            assert!(value < Uint::from(2).pow(Uint::from(bits)));
            value
        } else {
            self.base_field.random_pkcs_3(rng).as_montgomery()
        }
    }
}

impl Display for ModPGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DH-{}", self.base_field.modulus().bit_len())?;
        if let Some(l) = self.private_value_length {
            write!(f, "-{l}")?;
        }
        Ok(())
    }
}

impl Debug for ModPGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DH({}, {})",
            self.base_field.modulus(),
            self.generator().to_uint()
        )
    }
}

impl KeyAgreementAlgorithm for ModPGroup {
    fn subject_public_key(&self, pubkey: &SubjectPublicKeyInfo) -> Result<PublicKey> {
        let public = self.el_from_bitstring(&pubkey.subject_public_key)?;
        let public = self.el_to_bytes(public);
        Ok(PublicKey(public))
    }

    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey, PublicKey) {
        let private = self.generate_private_key(rng);
        let public = self.private_to_public_key(private);
        let public = self.el_to_bytes(public);
        (PrivateKey(Box::new(private)), PublicKey(public))
    }

    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>> {
        let private: &Uint = private
            .0
            .as_ref()
            .downcast_ref()
            .ok_or(anyhow!("Invalid private key"))?;
        let public = self.el_from_bytes(&public.0)?;
        let shared = public.pow_ct(*private);
        Ok(self.el_to_bytes(shared))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    /// ICAEO 9303-11 G-10 example G.2
    #[test]
    fn test_example_1() {
        let prime = hex!(
            "B10B8F96 A080E01D DE92DE5E AE5D54EC
            52C99FBC FB06A3C6 9A6A9DCA 52D23B61
            6073E286 75A23D18 9838EF1E 2EE652C0
            13ECB4AE A9061123 24975C3C D49B83BF
            ACCBDD7D 90C4BD70 98488E9C 219A7372
            4EFFD6FA E5644738 FAA31A4F F55BCCC0
            A151AF5F 0DC8B4BD 45BF37DF 365C1A65
            E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
        );
        let generator = hex!(
            "A4D1CBD5 C3FD3412 6765A442 EFB99905
            F8104DD2 58AC507F D6406CFF 14266D31
            266FEA1E 5C41564B 777E690F 5504F213
            160217B4 B01B886A 5E91547F 9E2749F4
            D7FBD7D3 B9A92EE1 909D0D22 63F80A76
            A6A24C08 7A091F53 1DBF0A01 69B6A28A
            D662A4D1 8E73AFA3 2D779D59 18D08BC8
            858F4DCE F97C2A24 855E6EEB 22B3B2E5"
        );
        let _order = hex!(
            "F518AA87 81A8DF27 8ABA4E7D 64B7CB9D
            49462353"
        );

        let field = PrimeField::from_modulus(Uint::from_be_slice(&prime));
        let generator = field.from(Uint::from_be_slice(&generator));
        let modp = ModPGroup::from_generator(generator, None);

        let term_private_key = hex!("5265030F 751F4AD1 8B08AC56 5FC7AC95 2E41618D");
        let term_public_key = hex!(
            "23FB3749 EA030D2A 25B278D2 A562047A
            DE3F01B7 4F17A154 02CB7352 CA7D2B3E
            B71C343D B13D1DEB CE9A3666 DBCFC920
            B49174A6 02CB4796 5CAA73DC 702489A4
            4D41DB91 4DE9613D C5E98C94 160551C0
            DF86274B 9359BC04 90D01B03 AD54022D
            CB4F57FA D6322497 D7A1E28D 46710F46
            1AFE710F BBBC5F8B A166F431 1975EC6C"
        );
        let term_private = Uint::from_be_slice(&term_private_key);
        let term_public = modp.private_to_public_key(term_private);
        let result = modp.el_to_octet_string(term_public);
        assert_eq!(result, term_public_key);

        let chip_private_key = hex!("66DDAFEA C1609CB5 B963BB0C B3FF8B3E 047F336C");
        let chip_public_key = hex!(
            "78879F57 225AA808 0D52ED0F C890A4B2
            5336F699 AA89A2D3 A189654A F70729E6
            23EA5738 B26381E4 DA19E004 706FACE7
            B235C2DB F2F38748 312F3C98 C2DD4882
            A41947B3 24AA1259 AC22579D B93F7085
            655AF308 89DBB845 D9E6783F E42C9F24
            49400306 254C8AE8 EE9DD812 A804C0B6
            6E8CAFC1 4F84D825 8950A91B 44126EE6"
        );
        let chip_private = Uint::from_be_slice(&chip_private_key);
        let chip_public = modp.private_to_public_key(chip_private);
        let result = modp.el_to_octet_string(chip_public);
        assert_eq!(result, chip_public_key);

        let shared_secret = hex!(
            "5BABEBEF 5B74E5BA 94B5C063 FDA15F1F
            1CDE9487 3EE0A5D3 A2FCAB49 F258D07F
            544F13CB 66658C3A FEE9E727 389BE3F6
            CBBBD321 28A8C21D D6EEA3CF 7091CDDF
            B08B8D00 7D40318D CCA4FFBF 51208790
            FB4BD111 E5A968ED 6B6F08B2 6CA87C41
            0B3CE0C3 10CE104E ABD16629 AA48620C
            1279270C B0750C0D 37C57FFF E302AE7F"
        );
        let chip = term_public.pow_ct(chip_private);
        let term = chip_public.pow_ct(term_private);
        assert_eq!(modp.el_to_bytes(chip), shared_secret);
        assert_eq!(modp.el_to_bytes(term), shared_secret);

        let mapped_generator = hex!(
            "7C9CBFE9 8F9FBDDA 8D143506 FA7D9306
            F4CB17E3 C71707AF F5E1C1A1 23702496
            84D64EE3 7AF44B8D BD9D45BF 6023919C
            BAA027AB 97ACC771 666C8E98 FF483301
            BFA4872D EDE9034E DFACB708 14166B7F
            36067682 9B826BEA 57291B5A D69FBC84
            EF1E7790 32A30580 3F743417 93E86974
            2D401325 B37EE856 5FFCDEE6 18342DC5"
        );
        let generator = field.from(Uint::from_be_slice(&mapped_generator));
        let modp = ModPGroup::from_generator(generator, None);

        let term_private_key = hex!("89CCD99B 0E8D3B1F 11E1296D CA68EC53 411CF2CA");
        let term_public_key = hex!(
            "00907D89 E2D425A1 78AA81AF 4A7774EC
            8E388C11 5CAE6703 1E85EECE 520BD911
            551B9AE4 D04369F2 9A02626C 86FBC674
            7CC7BC35 2645B616 1A2A42D4 4EDA80A0
            8FA8D61B 76D3A154 AD8A5A51 786B0BC0
            71470578 71A92221 2C5F67F4 31731722
            36B7747D 1671E6D6 92A3C7D4 0A0C3C5C
            E397545D 015C175E B5130551 EDBC2EE5 D4"
        );
        let term_private = Uint::from_be_slice(&term_private_key);
        let term_public = modp.private_to_public_key(term_private);
        let result = modp.el_to_octet_string(term_public);
        // NOTE: This example is odd in that the public key has a leading zero byte
        // added for compatibility with DER INTEGER encoding, but in the APDU this
        // byte is omitted. However, the tag-length is as if the byte is there.
        // TODO: Check what APDU length says and contact standards authors.
        assert_eq!(result, term_public_key[1..]);
    }
}
