mod bsi_tr03111;
mod buf;

pub use self::{
    bsi_tr03111::BsiTr031111Codec,
    buf::{BufCodec, BufCodecParent, BufMutCodec},
};
use {
    anyhow::Result,
    bytes::{Buf, BufMut},
};

pub trait Codec<T> {
    type Parent;
    fn encode<B: BufMut>(&self, buffer: &mut B, value: T);
    fn decode<B: Buf>(&self, buffer: &mut B, parent: Self::Parent) -> Result<T>;
}
