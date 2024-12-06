//! Helper traits to extend [`Buf`] and [`BufMut`] with codec methods.
use {
    super::Codec,
    anyhow::Result,
    bytes::{Buf, BufMut},
};

pub trait BufCodec<C, T>
where
    C: Codec<T>,
    C::Parent: Default,
{
    fn get_codec(&mut self, codec: &C) -> Result<T>;
}

pub trait BufCodecParent<C, T>
where
    C: Codec<T>,
{
    fn get_codec_parent(&mut self, codec: &C, parent: C::Parent) -> Result<T>;
}

pub trait BufMutCodec<C, T>
where
    C: Codec<T>,
{
    fn put_codec(&mut self, codec: &C, value: T);
}

impl<B, C, T> BufCodec<C, T> for B
where
    B: Buf,
    C: Codec<T>,
    C::Parent: Default,
{
    fn get_codec(&mut self, codec: &C) -> Result<T> {
        codec.decode(self, C::Parent::default())
    }
}

impl<B, C, T> BufCodecParent<C, T> for B
where
    B: Buf,
    C: Codec<T>,
{
    fn get_codec_parent(&mut self, codec: &C, parent: C::Parent) -> Result<T> {
        codec.decode(self, parent)
    }
}

impl<B, C, T> BufMutCodec<C, T> for B
where
    B: BufMut,
    C: Codec<T>,
{
    fn put_codec(&mut self, codec: &C, value: T) {
        codec.encode(self, value);
    }
}
