//! ICAO 9303-11 section 9.4
use {
    super::{BsiTr031111Codec, Codec},
    crate::crypto::groups::{EllipticCurve, EllipticCurvePoint},
    anyhow::{anyhow, ensure, Result},
    bytes::{Buf, BufMut, BytesMut},
    const_oid::ObjectIdentifier,
    der::Encode,
    ruint::Uint,
    tracing::warn,
};

/// How to handle correctable errors when decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leniency {
    /// Correct errors
    Allow,

    /// Correct, but log a warning.
    Warn,

    /// Be strict and return an error.
    Strict,
}

/// The encodings from ICAO 9303-11 section 9.4.
#[derive(Clone, Copy, Debug)]
pub struct Icao9303Codec {
    /// Non-canonical length encoding.
    non_minimal_length: Leniency,

    /// Leading zeros in integers.
    leading_zeros: Leniency,

    /// Whether to enforce strict order when reading sequences.
    read_order: Leniency,

    /// How to handle unknown tags.
    unknown_tag: Leniency,

    /// Allow missing cofactors in elliptic curves.
    /// When missing, the cofactor is assumed to be 1.
    missing_cofactor: Leniency,
}

/// Default behaviour is to warn.
impl Default for Icao9303Codec {
    fn default() -> Self {
        Self {
            non_minimal_length: Leniency::Warn,
            leading_zeros: Leniency::Warn,
            read_order: Leniency::Warn,
            unknown_tag: Leniency::Strict,
            missing_cofactor: Leniency::Warn,
        }
    }
}

pub struct BerSize(usize);

pub struct PublicKeyRSA<U> {
    oid: ObjectIdentifier,
    modulus: U,
    public_exponent: U,
}

pub struct PublicKeyDH<U, V> {
    oid: ObjectIdentifier,
    modulus: U,
    order: V,
    generator: U,
    public_key: U,
}

fn lenient(leniency: Leniency, msg: &'static str) -> Result<()> {
    match leniency {
        Leniency::Strict => Err(anyhow!(msg)),
        Leniency::Warn => {
            warn!(msg);
            Ok(())
        }
        Leniency::Allow => Ok(()),
    }
}

impl Codec<BerSize> for Icao9303Codec {
    type Parent = ();

    fn encoded_size(&self, value: BerSize) -> usize {
        match value.0.ilog2() {
            ..8 => 1,
            n => 1 + (n as usize + 7) / 8,
        }
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: BerSize) {
        if value.0 < 128 {
            buffer.put_u8(value.0 as u8);
        } else {
            let be = value.0.to_be_bytes();
            let trim = be.iter().position(|&b| b != 0).unwrap_or(0);
            let trimmed = &be[trim..];
            buffer.put_u8(0x80 | trimmed.len() as u8);
            buffer.put_slice(trimmed);
        }
    }

    fn decode<B: Buf>(&self, buffer: &mut B, _parent: Self::Parent) -> Result<BerSize> {
        ensure!(buffer.remaining() >= 1, "EOF when reading BerSize");
        let first = buffer.get_u8();
        if first < 128 {
            Ok(BerSize(first as usize))
        } else {
            const BYTES: usize = usize::BITS as usize / 8;
            let mut bytes = [0; BYTES];
            let len = (first & 0x7f) as usize;
            ensure!(len != 0, "Indefinite length not supported");
            ensure!(len != 127, "Reserved length not supported");
            ensure!(len <= BYTES, "Length too large");
            ensure!(buffer.remaining() >= len, "EOF when reading long BerSize");
            let trim = BYTES - len;
            buffer.copy_to_slice(&mut bytes[trim..]);
            if bytes[trim] == 0 || (len == 1 && bytes[trim] < 0x80) {
                lenient(self.non_minimal_length, "Length encoding is non-canonical.")?;
            }
            Ok(BerSize(usize::from_be_bytes(bytes)))
        }
    }
}

impl Codec<ObjectIdentifier> for Icao9303Codec {
    type Parent = ();

    fn encoded_size(&self, value: ObjectIdentifier) -> usize {
        value.as_bytes().len()
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: ObjectIdentifier) {
        buffer.put_slice(value.as_bytes());
    }

    fn decode<B: Buf>(&self, buffer: &mut B, _parent: Self::Parent) -> Result<ObjectIdentifier> {
        let bytes = buffer.copy_to_bytes(buffer.remaining());
        let oid = ObjectIdentifier::from_bytes(bytes.as_ref()).map_err(|e| anyhow!(e))?;
        Ok(oid)
    }
}

/// ICAO 9303-11 section 9.4.1 Data Object Encoding
///
/// An unsigned integer SHALL be converted to an octet string using the binary
/// representation of the integer in big-endian format. The minimum number of
/// octets SHALL be used, i.e. leading octets of value 0x00 MUST NOT be used.
impl<const BITS: usize, const LIMBS: usize> Codec<Uint<BITS, LIMBS>> for Icao9303Codec {
    type Parent = ();

    fn encoded_size(&self, value: Uint<BITS, LIMBS>) -> usize {
        value.byte_len()
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: Uint<BITS, LIMBS>) {
        buffer.put_slice(&value.to_be_bytes_trimmed_vec());
    }

    fn decode<B: Buf>(&self, buffer: &mut B, _parent: Self::Parent) -> Result<Uint<BITS, LIMBS>> {
        let bytes = buffer.copy_to_bytes(buffer.remaining());
        let trim = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        if trim > 0 {
            lenient(self.leading_zeros, "Leading zeros in integer.")?;
        }
        let bytes = &bytes[trim..];
        Uint::try_from_be_slice(bytes).ok_or_else(|| anyhow!("Value to large for target Uint"))
    }
}

/// ICAO 9303-11 section 9.4.1 Data Object Encoding
///
/// To encode elliptic curve points, uncompressed encoding according to
/// [TR-03111] SHALL be used.
impl<'a, const BITS: usize, const LIMBS: usize> Codec<EllipticCurvePoint<'a, Uint<BITS, LIMBS>>>
    for Icao9303Codec
{
    type Parent = &'a EllipticCurve<Uint<BITS, LIMBS>>;

    fn encoded_size(&self, value: EllipticCurvePoint<'a, Uint<BITS, LIMBS>>) -> usize {
        let codec = BsiTr031111Codec {
            compressed_points: false,
            ..Default::default()
        };
        codec.encoded_size(value)
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: EllipticCurvePoint<'a, Uint<BITS, LIMBS>>) {
        let codec = BsiTr031111Codec {
            compressed_points: false,
            ..Default::default()
        };
        codec.encode(buffer, value)
    }

    fn decode<B: Buf>(
        &self,
        buffer: &mut B,
        parent: Self::Parent,
    ) -> Result<EllipticCurvePoint<'a, Uint<BITS, LIMBS>>> {
        let codec = BsiTr031111Codec {
            compressed_points: false,
            ..Default::default()
        };
        codec.decode(buffer, parent)
    }
}

macro_rules! ber_size {
    ($codec:expr; $($tag:literal $value:expr)+) => {{
        let mut size = 0;
        $(
            let value_size = $codec.encoded_size($value);
            size += 1 + $codec.encoded_size(BerSize(value_size)) + value_size;
        )+
        size
    }};
}

macro_rules! ber_encoder {
    ($buffer:expr, $codec:expr; $($tag:literal $value:expr)+) => {
        // Data must be written in specifc tag order.
        $(
            $buffer.put_u8($tag);
            $codec.encode($buffer, BerSize($codec.encoded_size($value)));
            $codec.encode($buffer, $value);
        )+
    };
}

/// Helper macro to produce a BER decoder for a sequence of fields.
macro_rules! ber_decoder {
    ($buffer:expr, $codec:expr; $($n:literal $tag:literal $name:ident $type:ty)+) => {
        // Data can be read in any order.
        $(
            let mut $name: Option<$type> = None;
        )+
        let mut count = 0;
        while $buffer.has_remaining() {
            let tag = $buffer.get_u8();
            let len: BerSize = $codec.decode($buffer, ())?;
            ensure!($buffer.remaining() >= len.0, "Length too large");
            match tag {
                $(
                    $tag => {
                        if count != $n {
                            lenient($codec.read_order, concat!(stringify!($name), " out of order"))?;
                        }
                        ensure!($name.is_none(), concat!(stringify!($name), " already read"));
                        let mut bytes = $buffer.copy_to_bytes(len.0);
                        $name = Some($codec.decode(&mut bytes, ())?);
                    }
                )+
                _ => {
                    lenient($codec.unknown_tag, "Unknown tag")?;
                }
            }
            count += 1;
        }
        $(
            // TODO: Optional fields
            let $name = $name.ok_or_else(|| anyhow!(concat!(stringify!($name), " missing")))?;
        )+
    };
}

/// ICAO 9303-11 section 9.4.2 RSA Public Keys
impl<const BITS: usize, const LIMBS: usize> Codec<PublicKeyRSA<Uint<BITS, LIMBS>>>
    for Icao9303Codec
{
    type Parent = ();

    fn encoded_size(&self, value: PublicKeyRSA<Uint<BITS, LIMBS>>) -> usize {
        ber_size!(self;
            0x06 value.oid
            0x81 value.modulus
            0x82 value.public_exponent
        )
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: PublicKeyRSA<Uint<BITS, LIMBS>>) {
        ber_encoder!(buffer, self;
            0x06 value.oid
            0x81 value.modulus
            0x82 value.public_exponent
        );
    }

    fn decode<B: Buf>(
        &self,
        buffer: &mut B,
        _parent: Self::Parent,
    ) -> Result<PublicKeyRSA<Uint<BITS, LIMBS>>> {
        ber_decoder!(buffer, self;
            0 0x06 oid ObjectIdentifier
            1 0x81 modulus Uint<BITS, LIMBS>
            2 0x82 public_exponent Uint<BITS, LIMBS>
        );
        Ok(PublicKeyRSA {
            oid,
            modulus,
            public_exponent,
        })
    }
}

/// ICAO 9303-11 section 9.4.3 Diffie Hellman Public Keys
impl<const B0: usize, const L0: usize, const B1: usize, const L1: usize>
    Codec<PublicKeyDH<Uint<B0, L0>, Uint<B1, L1>>> for Icao9303Codec
{
    type Parent = ();

    fn encoded_size(&self, value: PublicKeyDH<Uint<B0, L0>, Uint<B1, L1>>) -> usize {
        ber_size!(self;
            0x06 value.oid
            0x81 value.modulus
            0x82 value.order
            0x83 value.generator
            0x84 value.public_key
        )
    }

    fn encode<B: BufMut>(&self, buffer: &mut B, value: PublicKeyDH<Uint<B0, L0>, Uint<B1, L1>>) {
        ber_encoder!(buffer, self;
            0x06 value.oid
            0x81 value.modulus
            0x82 value.order
            0x83 value.generator
            0x84 value.public_key
        );
    }

    fn decode<B: Buf>(
        &self,
        buffer: &mut B,
        _parent: Self::Parent,
    ) -> Result<PublicKeyDH<Uint<B0, L0>, Uint<B1, L1>>> {
        ber_decoder!(buffer, self;
            0 0x06 oid ObjectIdentifier
            1 0x81 modulus Uint<B0, L0>
            2 0x82 order Uint<B1, L1>
            3 0x83 generator Uint<B0, L0>
            4 0x84 public_key Uint<B0, L0>
        );
        Ok(PublicKeyDH {
            oid,
            modulus,
            order,
            generator,
            public_key,
        })
    }
}
