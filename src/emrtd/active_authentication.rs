use {
    super::Emrtd,
    crate::{
        asn1::{emrtd::EfDg15, SignatureAlgorithmIdentifier},
        crypto::public_key::PublicKey,
    },
    anyhow::Result,
    rand::{CryptoRng, Rng, RngCore},
};

impl Emrtd {
    /// Perform Active Authentication.
    /// Verifies chip authenticity by challenging it. The challenge must be
    /// correctly signed, verifiable through the public key provided in EF.DG15.
    pub fn active_authenticate(&mut self, mut rng: impl CryptoRng + RngCore) -> Result<()> {
        // The challenge
        let rnd_ifd: [u8; 8] = rng.gen();

        // Read EF.DG15
        let ef_dg15 = self.read_cached::<EfDg15>()?;

        // Grab the Active Authentication public key in DG15
        let pk = PublicKey::try_from(ef_dg15.active_authentication().clone())?;

        // Challenge IC
        let signature = self.commands().internal_authenticate(&rnd_ifd)?;

        // Verify signature
        pk.verify(
            &rnd_ifd,
            &signature,
            &SignatureAlgorithmIdentifier::RsaIso9796withMR,
        )?;

        Ok(())
    }
}
