use {
    super::Emrtd,
    anyhow::{anyhow, ensure, Result},
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
        let (status, data) = self.card.send_apdu(&[0x00, 0x84, 0x00, 0x00, 0x08])?;
        if !status.is_success() {
            return Err(anyhow!("Failed to get challenge: {}", status));
        }
        ensure!(status.data_remaining() == None);
        ensure!(data.len() == 8);
        Ok(data)
    }

    /// Send EXTERNAL AUTHENTICATE command.
    pub fn external_authenticate(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(data.len(), 0x28);
        let mut apdu = vec![0x00, 0x82, 0x00, 0x00, 0x28];
        apdu.extend_from_slice(data);
        apdu.push(0x00);
        let (status, data) = self.card.send_apdu(&apdu)?;
        if !status.is_success() {
            return Err(anyhow!("Failed to authenticate: {}", status));
        }
        Ok(data)
    }

    /// Send MSE:Set AT command.
    pub fn mset_at(&mut self, at: u16, data: &[u8]) -> Result<()> {
        let mut apdu = vec![0x00, 0x22];
        let p1p2 = &[(at >> 8) as u8, at as u8];
        apdu.extend_from_slice(p1p2);
        apdu.push(data.len().try_into()?);
        apdu.extend_from_slice(data);

        let (status, data) = self.card.send_apdu(&data)?;
        ensure!(status.is_success());
        ensure!(data.is_empty());
        Ok(())
    }

    pub fn general_authenticate(&mut self, data: &[u8], last: bool) -> Result<Vec<u8>> {
        let mut apdu = vec![0x00, 0x86, 0x00, 0x00];
        if !last {
            apdu[0] |= 0x10;
        };
        apdu.push(2 + u8::try_from(data.len())?);
        apdu.push(0x7c); // Dynamic authentication
        apdu.push(data.len().try_into()?);
        apdu.extend_from_slice(data);
        apdu.push(0x00); // Allow response length up to 256 bytes

        let (status, data) = self.card.send_apdu(&apdu)?;
        if !status.is_success() {
            return Err(anyhow!("Failed to authenticate: {}", status));
        }

        Ok(data)
    }
}
