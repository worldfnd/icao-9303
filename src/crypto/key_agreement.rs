use {
    super::{
        codec::BsiTr031111Codec,
        dh::DHPublicKey,
        ecdsa::ECPublicKey,
        groups::{EllipticCurve, EllipticCurvePoint, ModPGroup},
        mod_ring::{ModRingElementRef, RingRefExt},
        Codec, CryptoCoreRng, PrivateKey, PublicKey,
    },
    anyhow::{anyhow, bail, ensure, Result},
    num_traits::Inv,
    ruint::aliases::U4096,
    std::fmt::Debug,
};

type U521 = ruint::Uint<521, 9>;

/// Object safe trait for key agreement algorithms
pub trait KeyAgreementAlgorithm: Debug {
    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey>;
    fn parse_private_key(&self, bytes: &[u8]) -> Result<PrivateKey>;
    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey, PublicKey);
    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>>;
}

pub trait DiffieHellman {
    fn generate_private_key(&self, rng: &mut dyn CryptoCoreRng) -> Vec<u8>;
    fn private_to_public(&self, private: &[u8]) -> Result<Vec<u8>>;
    fn shared_secret(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>>;
}

impl KeyAgreementAlgorithm for ModPGroup<U4096, U4096> {
    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey> {
        let int: ModRingElementRef<_> =
            BsiTr031111Codec::default().decode(&mut &bytes[..], self.base_field())?;
        let dhkey = DHPublicKey {
            group: self.clone(),
            key:   int.to_uint(),
        };
        Ok(PublicKey::DH(dhkey))
    }

    fn parse_private_key(&self, bytes: &[u8]) -> Result<PrivateKey> {
        let int = self
            .scalar_field()
            .from(U4096::from_be_slice(bytes))
            .to_uint();
        Ok(PrivateKey(Box::new(int)))
    }

    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey, PublicKey) {
        let private = self.base_field().random(rng).to_uint();
        let public = self.generator().pow_ct(private);
        let public = PublicKey::DH(DHPublicKey {
            group: self.clone(),
            key:   public.to_uint(),
        });
        (PrivateKey(Box::new(private)), public)
    }

    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>> {
        let private: &U4096 = private
            .0
            .as_ref()
            .downcast_ref()
            .ok_or(anyhow!("Invalid private key"))?;
        let public = if let PublicKey::DH(key) = public {
            key
        } else {
            bail!("Provided public key is not EC")
        };
        let key = public.group.base_field().from(public.key);
        let shared = key.pow_ct(*private);
        let mut buf = Vec::new();
        BsiTr031111Codec::default().encode(&mut buf, shared);
        Ok(buf)
    }
}

impl KeyAgreementAlgorithm for EllipticCurve<U521> {
    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey> {
        let point: EllipticCurvePoint<_> =
            BsiTr031111Codec::default().decode(&mut &bytes[..], self)?;
        let eckey = ECPublicKey {
            curve: self.clone(),
            point: (point.x().unwrap().to_uint(), point.y().unwrap().to_uint()),
        };
        Ok(PublicKey::EC(eckey))
    }

    fn parse_private_key(&self, bytes: &[u8]) -> Result<PrivateKey> {
        let int = self
            .scalar_field()
            .from(U521::from_be_slice(bytes))
            .as_montgomery();
        Ok(PrivateKey(Box::new(int)))
    }

    fn generate_key_pair(&self, rng: &mut dyn super::CryptoCoreRng) -> (PrivateKey, PublicKey) {
        let private = self.scalar_field().random(rng);
        let public = self.generator() * private;
        (
            PrivateKey(Box::new(private.as_montgomery())),
            PublicKey::EC(public.into()),
        )
    }

    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>> {
        let private = self.scalar_field().from_montgomery(
            *private
                .0
                .as_ref()
                .downcast_ref::<U521>()
                .ok_or(anyhow!("Invalid private key"))?,
        );
        let public = if let PublicKey::EC(key) = public {
            key
        } else {
            bail!("Provided public key is not EC")
        };
        let (_, shared) = ecka(private, public)?;
        Ok(shared)
    }
}

/// Elliptic Curve Key Agreement
/// See TR-03111 section 4.3.1
pub fn ecka<'a>(
    private_key: ModRingElementRef<'a, U521>,
    public_key: &'a ECPublicKey<U521>,
) -> Result<(EllipticCurvePoint<'a, U521>, Vec<u8>)> {
    let curve = &public_key.curve;
    let point = public_key.point()?;
    ensure!(private_key.ring() == curve.scalar_field());
    let h = curve.cofactor();
    let l = curve.scalar_field().from(h).inv().unwrap();
    let q = point.mul_uint(h);
    let s_ab = q * (private_key * l);
    ensure!(s_ab != curve.infinity());
    let mut buf = Vec::new();
    BsiTr031111Codec::default().encode(&mut buf, s_ab.x().unwrap());
    Ok((s_ab, buf))
}
