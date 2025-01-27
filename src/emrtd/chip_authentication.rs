use {
    super::Emrtd,
    crate::{
        asn1::emrtd::{security_info::SymmetricCipher, EfDg14},
        emrtd::secure_messaging::construct_secure_messaging,
    },
    anyhow::Result,
    der::asn1::ObjectIdentifier as Oid,
    rand::{CryptoRng, RngCore},
};

impl Emrtd {
    pub fn chip_authenticate(&mut self, mut rng: impl CryptoRng + RngCore) -> Result<()> {
        // TODO: Some passports only have ChipAuthenticationPublicKeyInfo but no
        // ChipAuthenticationInfo. In this case, CA_(EC)DH_3DES_CBC_CBC should be
        // assumed.

        // Read EF.DG14
        let ef_dg14 = self.read_cached::<EfDg14>()?;
        dbg!(&ef_dg14);

        // Find the Chip Authentication Info in DG14
        let (ca, pk) = ef_dg14.chip_authentication().unwrap();
        println!("Using algorithm: {}", ca.protocol);

        let (algo, card_public_key) = pk.public_key.to_algorithm_public_key()?;

        // Generate keypair
        let (private_key, public_key) = algo.generate_key_pair(&mut rng);

        // Compute shared secret
        let shared_secret = algo.key_agreement(&private_key, &card_public_key)?;

        // Initiate Chip Authentication
        // ICAO-9303-11 section 6.2
        // 2. The terminal sends the public key to the eMRTD.
        //
        // For AES we need to use 6.2.4.2

        // Send MSE Set AT to select the Chip Authentication protocol.
        self.mset_at_chip_auth(ca.protocol.into(), pk.key_id)?;

        // Send the public key using general authenticate
        let data = self
            .commands()
            .general_authenticate(&[(0x80, public_key.as_ref())], true)?;
        println!("==> General Authenticate: {}", hex::encode(data));

        // Keys should now have been changed.
        let cipher = SymmetricCipher::Aes256;
        self.set_secure_messaging(construct_secure_messaging(cipher, &shared_secret, 0));

        Ok(())
    }

    fn mset_at_chip_auth(&mut self, protocol: Oid, key_id: Option<u64>) -> Result<()> {
        // Send MSE Set AT to select the Chip Authentication protocol.
        if let Some(id) = key_id {
            self.commands().mset_at(0x41a4, &[
                (0x80, protocol.as_bytes()), // Cryptographic mechanism
                (0x84, &[id.try_into()?]),   // Key reference
            ])
        } else {
            self.commands().mset_at(
                0x41a4,
                &[(0x80, protocol.as_bytes())], // Cryptographic mechanism
            )
        }
    }
}
