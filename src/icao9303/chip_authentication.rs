use {
    super::Icao9303,
    crate::{
        icao9303::{files::FileId, secure_messaging::SymmetricCipher, SecurityInfo},
        tr03110::{oid_name, ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo},
        tr03111::{ecka, ECAlgoParameters, EllipticCurve, ID_EC_PUBLIC_KEY},
    },
    anyhow::{anyhow, ensure, Result},
    der::{
        asn1::{AnyRef, ObjectIdentifier as Oid, SetOfVec},
        Decode, Tagged,
    },
    rand::{CryptoRng, RngCore},
};

impl Icao9303 {
    pub fn chip_authenticate(&mut self, rng: impl CryptoRng + RngCore) -> Result<()> {
        // Read EF.DG14
        let ef_dg14 = self.read_file_cached(FileId::Dg14).unwrap().unwrap();

        println!("DG14: {}", hex::encode(&ef_dg14));
        let tagged = AnyRef::from_der(&ef_dg14)?;
        ensure!(tagged.tag() == 0x6E.try_into().unwrap());

        // Find the Chip Authentication Info
        let mut ca = None;
        let mut pk = None;
        for security_info in SetOfVec::<SecurityInfo>::from_der(tagged.value())?.iter() {
            dbg!(security_info.protocol, oid_name(security_info.protocol));
            if let Ok(found_ca) = ChipAuthenticationInfo::try_from(security_info) {
                ca = Some(found_ca);
            }
            if let Ok(found_pk) = ChipAuthenticationPublicKeyInfo::try_from(security_info) {
                pk = Some(found_pk);
            }
        }
        let ca = ca.ok_or_else(|| anyhow!("Chip Authentication Info not found"))?;
        let pk = pk.ok_or_else(|| anyhow!("Chip Authentication Public Key Info not found"))?;
        println!("Using algorithm: {}", ca.algorithm_name());

        ensure!(pk.chip_authentication_public_key.algorithm.algorithm == ID_EC_PUBLIC_KEY);
        let ec_params = match pk.chip_authentication_public_key.algorithm.parameters {
            ECAlgoParameters::EcParameters(ec_params) => ec_params,
            _ => return Err(anyhow!("Expected ECParameters")),
        };

        let curve = EllipticCurve::from_parameters(&ec_params)?;
        dbg!(curve);

        let card_public_key = pk
            .chip_authentication_public_key
            .subject_public_key
            .as_bytes()
            .unwrap();
        let card_public_key = curve.pt_from_bytes(card_public_key)?;
        dbg!(card_public_key);

        // Generate ephemeral keypair
        let mut rng = rand::thread_rng();
        let private_key = curve.scalar_field().random_nonzero(&mut rng);
        let public_key = private_key * curve.generator();
        dbg!(private_key);
        dbg!(public_key);

        let (s, z) = ecka(private_key, card_public_key)?;
        dbg!(&s, hex::encode(&z));

        // Initiate Chip Authentication
        // ICAO-9303-11 section 6.2
        // 2. The terminal sends the public key to the eMRTD.
        //
        // For AES we need to use 6.2.4.2

        // Send MSE Set AT to select the Chip Authentication protocol.
        self.mset_at(ca.protocol, pk.key_id)?;

        // Send the public key using general authenticate
        let data = self.general_authenticate(&public_key.to_bytes())?;
        println!("==> General Authenticate: {}", hex::encode(data));

        // Keys should now have been changed.
        let cipher = SymmetricCipher::Aes256;
        self.set_secure_messaging(cipher.construct(&z));

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