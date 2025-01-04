//! ECDSA signature verification implementation

use {
    super::{
        groups::EllipticCurvePoint,
        mod_ring::{ModRingElementRef, UintMont},
    },
    crate::asn1::public_key_info::PubkeyAlgorithmIdentifier,
    anyhow::{anyhow, bail, ensure, Result},
    der::{Decode, Encode},
    num_traits::Inv,
};

#[derive(Clone, Debug)]
pub struct ECPublicKey<'c, U: UintMont> {
    point: EllipticCurvePoint<'c, U>,
}

#[derive(Debug, Clone)]
pub struct ECSignature<'a, U: UintMont> {
    r: ModRingElementRef<'a, U>,
    s: ModRingElementRef<'a, U>,
}

impl<'c, U: UintMont> ECPublicKey<'c, U> {
    pub fn new(point: EllipticCurvePoint<'c, U>) -> Self {
        Self { point }
    }

    pub fn verify(
        &self,
        message_hash: ModRingElementRef<'c, U>,
        signature: &ECSignature<'c, U>,
    ) -> Result<()> {
        let ECSignature { r, s } = signature;

        // w = s^(-1) mod n
        let w = s.inv().ok_or_else(|| anyhow!("Invalid s value"))?;

        // u1 = e * w mod n
        let u1 = message_hash * w;
        // u2 = r * w mod n
        let u2 = *r * w;

        // Q = u1*G + u2*Q
        let q = self.point.curve().generator() * u1 + self.point * u2;

        // Grab x of the Q point
        let x = q.x().unwrap();

        ensure!(x == *r);

        Ok(())
    }
}

impl<'c, U: UintMont> TryFrom<&spki::SubjectPublicKeyInfoOwned> for ECPublicKey<'c, U> {
    type Error = anyhow::Error;
    fn try_from(spki_pk: &spki::SubjectPublicKeyInfoOwned) -> anyhow::Result<Self, anyhow::Error> {
        let algo = PubkeyAlgorithmIdentifier::from_der(&spki_pk.algorithm.to_der()?)?;
        match algo {
            PubkeyAlgorithmIdentifier::Ec(params) => {
                let point_bytes = spki_pk.subject_public_key.as_bytes();

                todo!();
            }
            _ => bail!("SubjectPublicKeyInfo not EC-variant"),
        }
    }
}
