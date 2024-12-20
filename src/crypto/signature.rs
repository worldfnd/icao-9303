//! Signature verification for SOD

use {
    crate::asn1::{emrtd::EfSod, DigestAlgorithmIdentifier},
    anyhow::Result,
    der::{Decode, Encode},
};

impl EfSod {
    /// Verify the signature of the SOD
    pub fn verify_signature(&self) -> Result<()> {
        let signer = self.signer_info();

        // Message
        let message = self.encapsulated_content();

        // Message hash
        let digest = DigestAlgorithmIdentifier::from_der(&signer.digest_alg.to_der()?)?;
        let hash = digest.hash_der(message);
        eprintln!("DIGEST: {} = 0x{}", &digest, hex::encode(&hash));

        // Signature
        let signature = signer.signature.as_bytes();
        eprintln!("SIGNATURE: 0x{}", hex::encode(signature));

        dbg!(signer);

        todo!()
    }
}
