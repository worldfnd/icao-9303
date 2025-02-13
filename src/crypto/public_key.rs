use {
    super::{
        codec::{BsiTr031111Codec, BufMutCodec},
        dh::DHPublicKey,
        ecdsa::{ECPublicKey, ECSignature},
        groups::{EllipticCurve, EllipticCurvePoint},
        mod_ring::{ModRingElementRef, RingRefExt, UintMont},
        rsa::RSAPublicKey,
        PrivateKey,
    },
    crate::asn1::{
        public_key_info::SubjectPublicKeyInfo, signature_algorithm_identifier::EcdsaSigValue,
        SignatureAlgorithmIdentifier,
    },
    anyhow::{anyhow, bail, ensure, Result},
    der::{Decode, Encode},
    num_traits::Inv,
};

pub type PublicKey = Box<dyn PubKey>;

/// Trait for public keys that can be used for cryptographic operations
pub trait PubKey {
    /// Verify a signature
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        signature_algorithm: &SignatureAlgorithmIdentifier,
    ) -> Result<()>;

    /// Returns the public key as bytes following the BSI TR-03111
    /// representation
    fn to_bytes(&self) -> Vec<u8>;

    /// Perform a key agreement with another private key
    fn key_agreement(&self, private: &PrivateKey) -> Result<Vec<u8>>;
}

// Implement for each key type with UintMont constraint
impl<U: UintMont, S: UintMont> PubKey for DHPublicKey<U, S> {
    fn verify(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _algorithm: &SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        bail!("DH keys cannot verify signatures")
    }

    fn to_bytes(&self) -> Vec<u8> {
        let codec = BsiTr031111Codec::default();
        let mut bytes = Vec::new();
        // bytes.put_codec(&codec, &self.key);
        bytes
    }

    fn key_agreement(&self, _private: &PrivateKey) -> Result<Vec<u8>> {
        bail!("DH keys cannot perform key agreement")
    }
}

impl<U: UintMont> PubKey for ECPublicKey<U> {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        algorithm: &SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        let EcdsaSigValue { r, s } = EcdsaSigValue::from_der(signature)?;
        let r_elem = self
            .curve
            .scalar_field()
            .from(U::from_be_bytes(&r.as_bytes()));
        let s_elem = self
            .curve
            .scalar_field()
            .from(U::from_be_bytes(&s.as_bytes()));
        let ecsig = ECSignature {
            r: r_elem,
            s: s_elem,
        };

        self.verify(message, &ecsig, algorithm)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let codec = BsiTr031111Codec::default();
        let mut bytes = Vec::new();
        // bytes.put_codec(&codec, self.point()?);
        bytes
    }

    fn key_agreement(&self, private: &PrivateKey) -> Result<Vec<u8>> {
        let private = self.curve.scalar_field().from_montgomery(
            *private
                .0
                .as_ref()
                .downcast_ref::<U>()
                .ok_or(anyhow!("Invalid private key"))?,
        );
        let (_, shared) = ecka(private, self)?;
        Ok(shared)
    }
}

impl<U: UintMont> PubKey for RSAPublicKey<U> {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        algorithm: &SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        let sigint = U::from_be_bytes(signature);
        let rsasig = self.ring.from(sigint);

        self.verify(message, rsasig, algorithm)
    }

    fn to_bytes(&self) -> Vec<u8> {
        todo!("Implement RSA public key serialization")
    }

    fn key_agreement(&self, private: &PrivateKey) -> Result<Vec<u8>> {
        todo!("Implement RSA key agreement")
    }
}

impl TryFrom<SubjectPublicKeyInfo> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(info: SubjectPublicKeyInfo) -> Result<Self> {
        Ok(info.to_algorithm_public_key()?.1)
    }
}

impl TryFrom<&spki::SubjectPublicKeyInfoOwned> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(info: &spki::SubjectPublicKeyInfoOwned) -> Result<Self> {
        let local_info = SubjectPublicKeyInfo::from_der(&info.to_der()?)?;
        local_info.try_into()
    }
}

/// Elliptic Curve Key Agreement
/// See TR-03111 section 4.3.1
pub fn ecka<'a, U: UintMont>(
    private_key: ModRingElementRef<'a, U>,
    public_key: &'a ECPublicKey<U>,
) -> Result<(EllipticCurvePoint<'a, U>, Vec<u8>)> {
    let curve = &public_key.curve;
    let point = public_key.point()?;
    ensure!(private_key.ring() == curve.scalar_field());
    let h = curve.cofactor();
    let l = curve.scalar_field().from(h).inv().unwrap();
    let q = point.mul_uint(h);
    let s_ab = q * (private_key * l);
    ensure!(s_ab != curve.infinity());
    let mut buf = Vec::new();
    // BsiTr031111Codec::default().encode(&mut buf, s_ab.x().unwrap());
    Ok((s_ab, buf))
}
