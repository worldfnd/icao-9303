//! Diffie-Hellman key exchange on Mod P groups.

use {
    super::{
        super::mod_ring::{ModRing, ModRingElementRef, RingRefExt, UintMont},
        mul_group::MulGroup,
        CryptoCoreRng, CryptoGroup,
    },
    anyhow::{ensure, Result},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModPGroup<U: UintMont, V: UintMont> {
    base_field: ModRing<U>,
    scalar_field: ModRing<V>,
    generator_monty: U,
}

impl<U: UintMont, V: UintMont> ModPGroup<U, V> {
    pub fn new(modulus: U, generator: U, order: V) -> Result<Self> {
        ensure!(generator < modulus);
        let base_field = ModRing::from_modulus(modulus);
        let scalar_field = ModRing::from_modulus(order);
        let generator = base_field.from(generator);
        ensure!(
            generator.pow_ct(scalar_field.modulus()) == base_field.one(),
            "Generator has incorrect order"
        );
        Ok(Self {
            base_field,
            scalar_field,
            generator_monty: generator.as_montgomery(),
        })
    }

    #[inline]
    #[must_use]
    pub const fn base_field(&self) -> &ModRing<U> {
        &self.base_field
    }

    #[inline]
    #[must_use]
    pub const fn scalar_field(&self) -> &ModRing<V> {
        &self.scalar_field
    }

    #[inline]
    #[must_use]
    pub fn generator(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.generator_monty)
    }
}

impl<'s, U: 's + UintMont, V: 's + UintMont> CryptoGroup<'s> for ModPGroup<U, V> {
    type BaseElement = MulGroup<ModRingElementRef<'s, U>>;
    type ScalarElement = ModRingElementRef<'s, V>;

    fn generator(&'s self) -> Self::BaseElement {
        self.generator().into()
    }

    fn random_scalar(&'s self, rng: &mut dyn CryptoCoreRng) -> Self::ScalarElement {
        // TODO: Use the range [2, order - 2] as per
        // X9.42 (repro in RFC 2631) require [2, (q - 2)]
        self.scalar_field().random(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        named::{modp_160, modp_224, modp_256},
        test_dh, test_schnorr,
    };

    #[test]
    fn test_modp_160() {
        let group = modp_160();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_modp_224() {
        let group = modp_224();
        test_dh(&group);
        test_schnorr(&group);
    }

    #[test]
    fn test_modp_256() {
        let group = modp_256();
        test_dh(&group);
        test_schnorr(&group);
    }
}
