use {
    super::{pad, secure_messaging::Encrypted, seed_from_mrz, Emrtd},
    crate::crypto::cipher::{tdes::TDesCipher, Cipher, SMCipher},
    anyhow::{ensure, Result},
    rand::Rng,
    std::array,
};

impl Emrtd {
    pub fn basic_access_control(&mut self, rng: &mut impl Rng, mrz: &str) -> Result<()> {
        // eMRTD application must be selected
        self.select_emrtd_application()?;

        // Compute local randomness
        let rnd_ifd: [u8; 8] = rng.gen();
        let k_ifd: [u8; 16] = rng.gen();

        // Compute encryption / authentication keys from MRZ
        let seed = seed_from_mrz(mrz);
        let cipher = TDesCipher::from_seed(&seed)?;

        // GET CHALLENGE
        let rnd_ic = self.commands().get_challenge()?;

        // Construct authentication data
        let mut msg = vec![];
        msg.extend_from_slice(&rnd_ifd);
        msg.extend_from_slice(&rnd_ic);
        msg.extend_from_slice(&k_ifd);
        cipher.sm_enc(0, &mut msg)?;
        let mut msg_mac = msg.clone();
        pad(&mut msg_mac, cipher.block_size());
        msg.extend(cipher.mac(&msg_mac)?);

        // EXTERNAL AUTHENTICATE
        let mut resp_data = self.commands().external_authenticate(&msg)?;
        ensure!(resp_data.len() == 40);

        // Check MAC and decrypt response
        let mut msg_mac = resp_data[..32].to_vec();
        pad(&mut msg_mac, cipher.block_size());
        let mac = cipher.mac(&msg_mac)?;
        ensure!(&resp_data[32..] == &mac[..]);
        cipher.sm_dec(0, &mut resp_data[..32])?;
        let resp_data = &resp_data[..32];

        // Check nonce consistency
        ensure!(&resp_data[0..8] == &rnd_ic[..]);
        ensure!(&resp_data[8..16] == &rnd_ifd[..]);
        let k_ic: [u8; 16] = resp_data[16..].try_into().unwrap();

        // Construct seed and ssc for session keys
        let seed: [u8; 16] = array::from_fn(|i| k_ifd[i] ^ k_ic[i]);

        // Construct initial send sequence counter
        // See ICAO 9303-10 section 9.8.6.3
        let mut ssc_bytes = vec![];
        ssc_bytes.extend_from_slice(&rnd_ic[4..]);
        ssc_bytes.extend_from_slice(&rnd_ifd[4..]);
        let ssc: u64 = u64::from_be_bytes(ssc_bytes[..8].try_into().unwrap());

        // Add TDES session keys to secure messaging
        let tdes = Encrypted::new(TDesCipher::from_seed(&seed)?, ssc);
        self.secure_messaging = Box::new(tdes);

        Ok(())
    }
}
