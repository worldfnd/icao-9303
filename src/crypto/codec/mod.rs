mod bsi_tr03111;
mod buf;
mod icao_9303;

pub use self::{
    bsi_tr03111::BsiTr031111Codec,
    buf::{BufCodec, BufCodecParent, BufMutCodec},
};
use {
    anyhow::Result,
    bytes::{Buf, BufMut, BytesMut},
};

pub trait Codec<T> {
    type Parent;

    fn encoded_size(&self, value: T) -> usize {
        let mut buffer = BytesMut::new();
        self.encode(&mut buffer, value);
        buffer.len()
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: T);

    fn decode<B: Buf>(&self, buffer: &mut B, parent: Self::Parent) -> Result<T>;
}
