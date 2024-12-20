use {
    super::Emrtd,
    crate::{
        asn1::emrtd::{security_info::SymmetricCipher, EfDg14},
        emrtd::secure_messaging::construct_secure_messaging,
    },
    anyhow::{ensure, Result},
    der::asn1::ObjectIdentifier as Oid,
    rand::{CryptoRng, RngCore},
};

impl Emrtd {
    pub fn chip_authenticate(&mut self, mut rng: impl CryptoRng + RngCore) -> Result<()> {
        // TODO: Some passports only have ChipAuthenticationPublicKeyInfo but no ChipAuthenticationInfo. In this case, CA_(EC)DH_3DES_CBC_CBC should be assumed.

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
        self.mset_at(ca.protocol.into(), pk.key_id)?;

        // Send the public key using general authenticate
        let data = self.general_authenticate(public_key.as_ref())?;
        println!("==> General Authenticate: {}", hex::encode(data));

        // Keys should now have been changed.
        let cipher = SymmetricCipher::Aes256;
        self.set_secure_messaging(construct_secure_messaging(cipher, &shared_secret, 0));

        Ok(())
    }

    pub fn mset_at(&mut self, protocol: Oid, key_id: Option<u64>) -> Result<()> {
        // Send MSE Set AT to select the Chip Authentication protocol.
        let mut apdu = vec![0x00, 0x22, 0x41, 0xA4];
        apdu.push(0x00); // Placeholder length

        // Cryptographic mechanism: 0x80 <len> <OID>
        let protocol = protocol.as_bytes();
        apdu.push(0x80);
        apdu.push(protocol.len().try_into()?);
        apdu.extend_from_slice(protocol);

        // If the pivate key to be used has a reference, include it.
        if let Some(id) = key_id {
            apdu.push(0x84);
            apdu.push(0x01); // Assume id < 256
            apdu.push(id.try_into()?);
        }

        // Update length
        apdu[4] = (apdu.len() - 5).try_into()?;

        // Send MSE Set AT command to chip
        let (status, data) = self.send_apdu(&apdu)?;
        ensure!(status.is_success());
        ensure!(data.is_empty());
        Ok(())
    }

    pub fn general_authenticate(&mut self, public_key: &[u8]) -> Result<Vec<u8>> {
        // Send General Authenticate command to chip
        let mut apdu = vec![0x00, 0x86, 0x00, 0x00];
        apdu.push((public_key.len() + 4).try_into()?);
        apdu.push(0x7C);
        apdu.push((public_key.len() + 2).try_into()?);
        apdu.push(0x80);
        apdu.push(public_key.len().try_into()?);
        apdu.extend_from_slice(public_key);

        let (status, data) = self.send_apdu(&apdu)?;
        ensure!(status.is_success());
        Ok(data)
    }
}
