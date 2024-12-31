mod proxmark3;

use {crate::iso7816::StatusWord, anyhow::Result};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CardType {
    A(CardTypeA),
    B(CardTypeB),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CardTypeA {
    /// Unique Identifier
    uid: Vec<u8>,

    /// Select Acknowledge
    sak: u8,

    /// Answer to Request, Type A
    atqa: u16,

    /// Answer to Select
    ats: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CardTypeB {
    /// Unique Identifier
    uid: Vec<u8>,

    /// Answer to Request, Type B
    atqb: Vec<u8>,

    chip_id: u8,

    /// Answer to Select
    cid: u8,
}

pub trait NfcReader {
    // TODO: Should return card info, and reader/card capabilities like extended
    // length.
    fn connect(&mut self) -> Result<Option<CardType>>;
    fn disconnect(&mut self) -> Result<()>;
    fn send_apdu(&mut self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)>;
}

pub fn connect_reader() -> Result<Box<dyn NfcReader>> {
    Ok(Box::new(proxmark3::Proxmark3::new()?))
}
