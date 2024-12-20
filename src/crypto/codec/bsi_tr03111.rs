//! Implements the encodings from BSI TR-03111 section 3.
use {
    super::Codec,
    crate::crypto::{
        groups::{EllipticCurve, EllipticCurvePoint},
        mod_ring::{ModRingElement, RingRef, RingRefExt},
    },
    anyhow::{anyhow, ensure, Result},
    bytes::{Buf, BufMut},
    ruint::Uint,
};

/// The encodings from BSI TR-03111
#[derive(Clone, Copy, Debug)]
pub struct BsiTr031111Codec {
    /// Byte length for uints (defaults to Uint::BYTES).
    pub uint_bytes: Option<usize>,

    /// Whether to write Elliptic curve points in compressed form.
    pub compressed_points: bool,
}

impl Default for BsiTr031111Codec {
    fn default() -> Self {
        Self {
            uint_bytes: None,
            compressed_points: true,
        }
    }
}

/// BSI TR-03111 3.1.2: Conversion between Integers and Octet Strings
impl<const BITS: usize, const LIMBS: usize> Codec<Uint<BITS, LIMBS>> for BsiTr031111Codec {
    type Parent = ();

    fn encode<B: BufMut>(&self, buffer: &mut B, value: Uint<BITS, LIMBS>) {
        let size = self.uint_bytes.unwrap_or(Uint::<BITS, LIMBS>::BYTES);
        assert!(value.byte_len() <= size, "Invalid byte length for uint");
        let bytes = value.to_be_bytes_vec();
        if size > bytes.len() {
            buffer.put_slice(&vec![0; size - bytes.len()]);
        }
        let trim = bytes.len().saturating_sub(size);
        assert!(bytes[..trim].iter().all(|b| *b == 0));
        buffer.put_slice(&bytes[trim..]);
    }

    fn decode<B: Buf>(&self, buffer: &mut B, _parent: Self::Parent) -> Result<Uint<BITS, LIMBS>> {
        let size = self.uint_bytes.unwrap_or(Uint::<BITS, LIMBS>::BYTES);
        ensure!(buffer.remaining() >= size, "Insufficient bytes remaining");
        let bytes = buffer.copy_to_bytes(size);
        let trim = bytes.len().saturating_sub(Uint::<BITS, LIMBS>::BYTES);
        Uint::try_from_be_slice(&bytes[trim..])
            .ok_or_else(|| anyhow!("Value to large for target Uint"))
    }
}

/// BSI TR-03111 3.1.3: Conversion between Field Elements and Octet Strings
impl<R, const BITS: usize, const LIMBS: usize> Codec<ModRingElement<R>> for BsiTr031111Codec
where
    R: RingRef<Uint = Uint<BITS, LIMBS>>,
{
    type Parent = R;

    fn encode<B: BufMut>(&self, buffer: &mut B, value: ModRingElement<R>) {
        let codec = Self {
            uint_bytes: Some(value.ring().modulus().byte_len()),
            ..Default::default()
        };
        codec.encode(buffer, value.to_uint());
    }

    fn decode<B: Buf>(&self, buffer: &mut B, parent: Self::Parent) -> Result<ModRingElement<R>> {
        let codec = Self {
            uint_bytes: Some(parent.modulus().byte_len()),
            ..Default::default()
        };
        let uint: Uint<BITS, LIMBS> = codec.decode(buffer, ())?;
        let reduced = uint % parent.modulus();
        Ok(parent.from(reduced))
    }
}

/// BSI TR-03111 3.2: Encoding Elliptic Curve Points
impl<'a, const BITS: usize, const LIMBS: usize> Codec<EllipticCurvePoint<'a, Uint<BITS, LIMBS>>>
    for BsiTr031111Codec
{
    type Parent = &'a EllipticCurve<Uint<BITS, LIMBS>>;

    fn encode<B: BufMut>(&self, buffer: &mut B, value: EllipticCurvePoint<'a, Uint<BITS, LIMBS>>) {
        match value.coordinates() {
            None => buffer.put_u8(0),
            Some((x, y)) => {
                if self.compressed_points {
                    let even = y.to_uint().bit(0);
                    buffer.put_u8(if even { 2 } else { 3 });
                    self.encode(buffer, x);
                } else {
                    buffer.put_u8(4);
                    self.encode(buffer, x);
                    self.encode(buffer, y);
                }
            }
        }
    }

    fn decode<B: Buf>(
        &self,
        buffer: &mut B,
        parent: Self::Parent,
    ) -> Result<EllipticCurvePoint<'a, Uint<BITS, LIMBS>>> {
        let byte = buffer.get_u8();
        match byte {
            0 => Ok(parent.infinity()),
            2 | 3 => {
                let want_even = byte == 2;
                let x = self.decode(buffer, parent.base_field())?;
                let p = parent
                    .from_x(x)
                    .ok_or_else(|| anyhow!("Invalid x coordinate"))?;
                let is_even = p.y().unwrap().to_uint().bit(0);
                Ok(if want_even == is_even { p } else { -p })
            }
            4 => {
                let x = self.decode(buffer, parent.base_field())?;
                let y = self.decode(buffer, parent.base_field())?;
                parent.from_affine(x, y)
            }
            _ => Err(anyhow!("Invalid byte for elliptic curve point")),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{super::BufCodecParent, *},
        crate::crypto::groups::named::brainpool_p256r1,
        hex_literal::hex,
    };

    // Example from BSI Worked Example for Extended Access Control (EAC) section 3.3
    #[test]
    fn test_codec() {
        let codec = BsiTr031111Codec::default();
        let curve = brainpool_p256r1();
        let sk_pcd = hex!(
            "75 22 87 F5 B0 2D E3 C4 BC 3E 17 94 51 18 C5 1B 23 C9 72 78 E4 CD 74 80 48 AC 56 BA \
             5B DC 3D 46"
        );
        let pk_pcd = hex!(
            "04 3D D2 9B BE 59 07 FD 21 A1 52 AD A4 89 5F AA E7 AC C5 5F 5E 50 EF BF DE 5A B0 C6 \
             EB 54 F1 98 D6 15 91 36 35 F0 FD F5 BE B3 83 E0 03 55 F8 2D 3C 41 ED 0D F2 E2 83 63 \
             43 3D FB 73 85 6A 15 DC 9F"
        );
        let sk_pcd: ModRingElement<_> = sk_pcd
            .as_ref()
            .get_codec_parent(&codec, curve.scalar_field())
            .unwrap();
        let pk_pcd: EllipticCurvePoint<_> =
            pk_pcd.as_ref().get_codec_parent(&codec, &curve).unwrap();
        assert_eq!(curve.generator() * sk_pcd, pk_pcd);
    }
}
