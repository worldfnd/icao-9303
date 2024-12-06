use {
    super::{
        groups::CryptoGroup,
        mod_ring::{ModRingElement, RingRef, RingRefExt},
    },
    anyhow::{ensure, Result},
    bytes::BufMut,
    ruint::Uint,
};

pub trait Codec<T> {
    type Parent;
    fn encode(&self, value: T) -> Vec<u8>;
    fn decode(&self, parent: Self::Parent, data: &[u8]) -> Result<T>;
}

// pub struct KeyAgreement<'a, G, C, D>
// where
//     G: CryptoGroup<'a>,
//     C: Codec<G::BaseElement>,
//     D: Codec<G::ScalarElement>,
// {
//     group:        G,
//     base_codec:   C,
//     scalar_codec: D,
// }

pub fn big_endian_uint<const BITS: usize, const LIMBS: usize>(
    value: Uint<BITS, LIMBS>,
    dst: &mut impl BufMut,
) {
    dst.put_slice(&value.to_be_bytes_vec());
}

/// BSI TR-03111 Codecs
pub struct BsiTr031111Codec;

/// BSI TR-03111 3.1.2
impl<const BITS: usize, const LIMBS: usize> Codec<Uint<BITS, LIMBS>> for BsiTr031111Codec {
    type Parent = ();

    fn encode(&self, value: Uint<BITS, LIMBS>) -> Vec<u8> {
        value.to_be_bytes_vec()
    }

    fn decode(&self, _parent: Self::Parent, data: &[u8]) -> Result<Uint<BITS, LIMBS>> {
        ensure!(data.len() == (BITS + 7) / 8, "Invalid length");
        Ok(Uint::from_be_slice(data))
    }
}

/// BSI TR-03111 3.1.3
impl<Ring: RingRef> Codec<ModRingElement<Ring>> for BsiTr031111Codec
where
    Self: Codec<Ring::Uint, Parent = ()>,
{
    type Parent = Ring;

    fn encode(&self, value: ModRingElement<Ring>) -> Vec<u8> {
        self.encode(value.to_uint())
    }

    fn decode(&self, ring: Self::Parent, data: &[u8]) -> Result<ModRingElement<Ring>> {
        let uint = self.decode((), data)?;
        Ok(ring.from(uint))
    }
}

// pub fn parse_uint_os<const B: usize, const L: usize>(os: &OctetString) ->
// Result<Uint<B, L>> {     // Get twos-complement big-endian bytes
//     let big_endian = os.as_bytes();

//     // TODO: Length should be exactly length of modulus in bytes.

//     // Ensure the number is not too large
//     ensure!(big_endian.len() <= 40, "Modulus is too large");

//     // Zero extend to 320 bits
//     let mut zero_extended = [0; 40];
//     zero_extended[40 - big_endian.len()..].copy_from_slice(big_endian);

//     // Parse as Uint
//     let uint = Uint::from_be_slice(&zero_extended);
//     Ok(uint)
// }
