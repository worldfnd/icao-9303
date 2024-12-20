//! RSA signature verification implementation
//!
//! To *not* do: Signing. This will remain verifying only. RSA a minefield
//! of pitfalls and security issues and no-one should create new signatures
//! using it. See e.g. https://blog.trailofbits.com/2019/07/08/fuck-rsa

use {
    super::mod_ring::{ModRing, ModRingElementRef, UintMont},
    anyhow::{ensure, Result},
    subtle::ConstantTimeEq,
};

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
}

#[cfg(test)]
mod tests {
    use {
        crate::asn1::{
            public_key_info::{PubkeyAlgorithmIdentifier, SubjectPublicKeyInfo},
            SignatureAlgorithmIdentifier,
        },
        anyhow::{ensure, Result},
        der::Decode,
        hex_literal::hex,
    };

    #[test]
    fn test_rsa_ssa_pss() -> Result<()> {
        let subject_public_key = hex!("30820222300d06092a864886f70d01010105000382020f003082020a0282020100becc9fedc6ebb2ede36493138cf8cee05da57b5abc35becf062e1cce9bb196edf4ff6dcaa8e61d65f898ea63a601e8234f395041e3621b4541e1429882064eecd13feff1bf6123e5ce23354dd337aa1bc78eb711c97602d8574a21b336461c7133eda48f6fe7386b55bf1d8e8691ae25bf63b4cfc793e7f82d787941fc34022e194ff98870622e0fc1da78d39e9ee14236639adbcaa66fb2f488a59ff478176125072dbfa8223df2f0ac98d1f0f15695a9278b08b0873decef880d378f0577c9b1f9488198f060dd140a365d1f90387cbc9f8ba68453cb1b1d198b2875c87dcae9bf61ff54c7722f770a6b42ce3cb59f3de3dce9457d361c5859c05071fba664da91fb1a9cad08089656c761201d890c0a829e5d0c63cc6c710478515962e6b5675183085b2d60011ddf1b727cb33cb9ba8a6c9ff5859c546626be9e9d59917690710d6d31f8a2a8c03be9d61016a6b41817eb61807436027db51c5200316131f4cc3f4367d317c18ee6383c41d841fca963c180cd8766e703f888d08f5ae3bb3d4e709cde248cea9c7fb08470b70f916fd1a453bff4473c28ace2ff2365da00d62fd4a90090c30b085d432671826711308384984bf8e1df6ae5dd584c224a39d32c16771663728653e4a6a2152bf423022d37b91596ad9e148b80a759b3d7cd8571b12694c3deea30e9fa7ea878c0c739aa6e2be75785fc9cd9d68ae0d4b7530203010001");
        let signature_algorithm = hex!("303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a203020120");
        let signature = hex!("31ac356deec3f3c8bf56e0306528aa7bd5bb01c7b5cf0588261a5a0f7f6e249922102b1c19c1786869ba431563f04f8c6b1b67245daf4b108f1c73bc3eaa4e944977ce7fd62f1d66ef36673fdb3cf91ecad8303e37c5d42f8a01e246dd0314140d7d3788ab4a7f52798dd603151ccb96da473669a757dc2c7b88912eb85dfbee44f047b7eec07bf94b10756f1c73b85b3b9a8bb0f8bcf3f6bdbeda53b4edae166f86b87bebe20f8d8acad2158fa67058133910169d7cd6519ffaa47e375d1f927e1a580f05c49a712f436d91062c208dd471c1093042398a930f4c03e398d0fa0d4fb2a1664723df050d42b251bd0e5d51a78d15709aca21aefb5212e19fb4c6");

        let der = SubjectPublicKeyInfo::from_der(&subject_public_key).unwrap();
        ensure!(matches!(der, SubjectPublicKeyInfo::Rsa(_)));

        let der = SignatureAlgorithmIdentifier::from_der(&signature_algorithm).unwrap();
        ensure!(matches!(der, SignatureAlgorithmIdentifier::Rsa(_)));

        dbg!(&der);

        Ok(())
    }
}
