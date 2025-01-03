//! ECDSA signature verification implementation

use {
    super::groups::CryptoGroup,
    anyhow::{anyhow, ensure, Result},
    num_traits::Inv,
};

#[derive(Clone, Debug)]
pub struct ECPublicKey<'g, G: CryptoGroup<'g>> {
    group: &'g G,
    point: G::BaseElement,
}

#[derive(Debug, Clone)]
pub struct ECSignature<'g, G: CryptoGroup<'g>> {
    r: G::ScalarElement,
    s: G::ScalarElement,
}

impl<'g, G: CryptoGroup<'g>> ECPublicKey<'g, G> {
    pub fn new(group: &'g G, point: G::BaseElement) -> Self {
        Self { group, point }
    }

    pub fn verify(
        &self,
        message_hash: &G::ScalarElement,
        signature: &ECSignature<'g, G>,
    ) -> Result<()> {
        let ECSignature { r, s } = signature;

        // w = s^(-1) mod n
        let w = s.inv().ok_or_else(|| anyhow!("Invalid s value"))?;

        // u1 = e * w mod n
        let u1 = *message_hash * w;
        // u2 = r * w mod n
        let u2 = *r * w;

        // Q = u1*G + u2*Q
        let q = self.group.generator() * u1 + self.point * u2;

        // Grab x of the Q point
        let x = self.group.x_of(&q).unwrap();

        ensure!(x == *r);

        Ok(())
    }
}
