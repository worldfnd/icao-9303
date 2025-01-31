#![cfg(feature = "pcsc")]

use {
    super::{CardType, NfcReader},
    crate::iso7816::StatusWord,
    anyhow::{anyhow, bail, ensure, Result},
    pcsc::*,
};

pub struct PCSC {
    ctx:  Context,
    card: Option<Card>,
}

impl PCSC {
    pub fn init() -> Result<Self> {
        // Establish a PC/SC context
        let ctx = Context::establish(Scope::User)
            .map_err(|e| anyhow!("Failed to establish context: {e}"))?;
        Ok(PCSC { ctx, card: None })
    }

    pub fn connect(&mut self) -> Result<()> {
        // List available readers
        let mut readers_buf = [0; 2048];
        let mut readers = self
            .ctx
            .list_readers(&mut readers_buf)
            .map_err(|e| anyhow!("Failed to list readers: {e}"))?;

        // Find first reader with card
        let card = readers
            .find_map(|reader| {
                self.ctx
                    .connect(reader, ShareMode::Shared, Protocols::ANY)
                    .ok()
            })
            .ok_or_else(|| anyhow!("No card found"))?;

        self.card = Some(card);

        Ok(())
    }

    pub fn send(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        let Some(card) = &self.card else {
            bail!("Not connected to a card")
        };
        let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
        let rapdu = card
            .transmit(apdu, &mut rapdu_buf)
            .map_err(|e| anyhow!("Failed to transmit APDU command to card: {e}"))?;
        ensure!(rapdu.len() >= 2);
        let (data, status) = rapdu.split_at(rapdu.len() - 2);
        let status = u16::from_be_bytes([status[0], status[1]]).into();
        Ok((status, data.to_vec()))
    }

    pub fn disconnect(&mut self) -> Result<()> {
        // pcsc::Card implements drop() with Disposition::ResetCard
        self.card = None;
        Ok(())
    }

    pub fn ctx(&self) -> &Context {
        &self.ctx
    }
    pub fn ctx_mut(&mut self) -> &mut Context {
        &mut self.ctx
    }
}

impl NfcReader for PCSC {
    fn connect(&mut self) -> Result<Option<CardType>> {
        self.connect()?;
        Ok(Some(CardType::Abstract))
    }

    fn disconnect(&mut self) -> Result<()> {
        self.disconnect()
    }

    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        self.send(apdu)
    }
}
