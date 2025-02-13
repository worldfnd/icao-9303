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
    std::fmt::Debug,
};

/// Object safe trait for key agreement algorithms
pub trait KeyAgreementAlgorithm: Debug {
    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey>;
    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey, PublicKey);
    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>>;
}

pub trait DiffieHellman {
    fn generate_private_key(&self, rng: &mut dyn CryptoCoreRng) -> Vec<u8>;
    fn private_to_public(&self, private: &[u8]) -> Result<Vec<u8>>;
    fn shared_secret(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>>;
}

// impl KeyAgreementAlgorithm for ModPGroup<DhUint, DhsUint> {
//    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey> {
//        let int: ModRingElementRef<_> =
//            BsiTr031111Codec::default().decode(&mut &bytes[..],
// self.base_field())?;        let dhkey = DHPublicKey {
//            group: self.clone(),
//            key:   int.to_uint(),
//        };
//        Ok(PublicKey::DH(dhkey))
//    }
//
//    fn generate_key_pair(&self, rng: &mut dyn CryptoCoreRng) -> (PrivateKey,
// PublicKey) {        let private = self.base_field().random(rng).to_uint();
//        let public = self.generator().pow_ct(private);
//        let public = PublicKey::DH(DHPublicKey {
//            group: self.clone(),
//            key:   public.to_uint(),
//        });
//        (PrivateKey(Box::new(private)), public)
//    }
//
//    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) ->
// Result<Vec<u8>> {        let private: &DhUint = private
//            .0
//            .as_ref()
//            .downcast_ref()
//            .ok_or(anyhow!("Invalid private key"))?;
//        let public = if let PublicKey::DH(key) = public {
//            key
//        } else {
//            bail!("Provided public key is not EC")
//        };
//        let key = public.group.base_field().from(public.key);
//        let shared = key.pow_ct(*private);
//        let mut buf = Vec::new();
//        BsiTr031111Codec::default().encode(&mut buf, shared);
//        Ok(buf)
//    }
//}

impl<U: crate::crypto::mod_ring::UintMont> KeyAgreementAlgorithm for EllipticCurve<U> {
    fn parse_public_key(&self, bytes: &[u8]) -> Result<PublicKey> {
        let point = self.generator();
        // let point: EllipticCurvePoint<_> =
        //    BsiTr031111Codec::default().decode(&mut &bytes[..], self)?;
        let eckey = ECPublicKey {
            curve: self.clone(),
            point: (
                U::from_be_bytes(&point.x().unwrap().to_uint().to_be_bytes()),
                U::from_be_bytes(&point.y().unwrap().to_uint().to_be_bytes()),
            ),
        };
        Ok(Box::new(eckey))
    }

    fn generate_key_pair(&self, rng: &mut dyn super::CryptoCoreRng) -> (PrivateKey, PublicKey) {
        let private = self.scalar_field().random(rng);
        let public = self.generator() * private;
        (
            PrivateKey(Box::new(private.as_montgomery())),
            Box::new(ECPublicKey::from(public)),
        )
    }

    fn key_agreement(&self, private: &PrivateKey, public: &PublicKey) -> Result<Vec<u8>> {
        public.key_agreement(private)
    }
}
