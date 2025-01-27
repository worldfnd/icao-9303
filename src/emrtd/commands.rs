use {
    super::{iso7816::Apdu, Emrtd},
    anyhow::{ensure, Result},
};

pub struct Commands<'a> {
    card: &'a mut Emrtd,
}

impl<'a> Commands<'a> {
    pub fn new(card: &'a mut Emrtd) -> Self {
        Self { card }
    }

    /// Send GET CHALLENGE command.
    /// Gets random nonce for authentication.
    ///
    /// See ICAO 9303-11 section 4.3.4.1.
    pub fn get_challenge(&mut self) -> Result<Vec<u8>> {
        let apdu = Apdu::new(0x00, 0x84, 0x00, 0x00, Some(8)).build()?;

        let (status, data) = self.card.send_apdu(&apdu)?;
        ensure!(status.is_success(), "Failed to get challenge: {}", status);
        ensure!(status.data_remaining() == None);
        ensure!(data.len() == 8);
        Ok(data)
    }

    /// Send EXTERNAL AUTHENTICATE command.
    pub fn external_authenticate(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(data.len() == 0x28);
        let apdu = Apdu::new(0x00, 0x82, 0x00, 0x00, None)
            .push_bytes(data)
            .build()?;

        let (status, data) = self.card.send_apdu(&apdu)?;
        ensure!(status.is_success(), "Failed to authenticate: {}", status);
        Ok(data)
    }

    /// Send MSE:Set AT command.
    pub fn mset_at(&mut self, at: u16, data: &[(u8, &[u8])]) -> Result<()> {
        let mut apdu = Apdu::new(0x00, 0x22, (at >> 8) as u8, at as u8, Some(0));
        for (tag, bytes) in data {
            apdu.push_tlv(*tag, bytes)?;
        }

        let (status, data) = self.card.send_apdu(&apdu.build()?)?;
        ensure!(status.is_success());
        ensure!(data.is_empty());
        Ok(())
    }

    /// Send GENERAL AUTHENTICATE command. Uses command chaining.
    /// Set `last` to false if more APDUs to be sent.
    pub fn general_authenticate(&mut self, data: &[(u8, &[u8])], last: bool) -> Result<Vec<u8>> {
        let mut apdu = Apdu::new(0x00, 0x86, 0x00, 0x00, None);
        apdu.dynamic_auth();
        if !last {
            apdu.chain();
        }
        for (tag, bytes) in data {
            apdu.push_tlv(*tag, bytes)?;
        }

        let (status, data) = self.card.send_apdu(&apdu.build()?)?;
        ensure!(status.is_success(), "Failed to authenticate: {}", status);

        Ok(data)
    }
}
