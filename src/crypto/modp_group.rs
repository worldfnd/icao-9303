//! Diffie-Hellman key exchange on Mod P groups.

use {
    super::{
        mod_ring::{ModRing, ModRingElementRef, RingRefExt, UintExp, UintMont},
        CryptoCoreRng, DiffieHellman,
    },
    anyhow::{ensure, Result},
    subtle::ConditionallySelectable,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ModPGroup<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    base_field:      ModRing<U>,
    scalar_field:    ModRing<V>,
    generator_monty: U,
}

impl<U, V> ModPGroup<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    pub fn new(modulus: U, generator: U, order: V) -> Result<Self> {
        ensure!(generator < modulus);
        let base_field = ModRing::from_modulus(modulus);
        let scalar_field = ModRing::from_modulus(order);
        let generator_monty = base_field.from(generator).as_montgomery();
        Ok(Self {
            base_field,
            scalar_field,
            generator_monty,
        })
    }

    pub fn base_field(&self) -> &ModRing<U> {
        &self.base_field
    }

    pub fn scalar_field(&self) -> &ModRing<V> {
        &self.scalar_field
    }

    pub fn generator(&self) -> ModRingElementRef<'_, U> {
        self.base_field.from_montgomery(self.generator_monty)
    }
}

// pub fn generate_private_key(&self, mut rng: impl CryptoRng + RngCore) -> Uint
// {     if let Some(bits) = self.private_value_length {
//         let mut value = rng.gen::<Uint>();
//         for b in bits..Uint::BITS {
//             value.set_bit(b, false);
//         }
//         value.set_bit(bits - 1, true);
//         assert!(value >= Uint::from(2).pow(Uint::from(bits - 1)));
//         assert!(value < Uint::from(2).pow(Uint::from(bits)));
//         value
//     } else {
//         self.base_field.random_pkcs_3(rng).as_montgomery()
//     }
// }

// pub fn private_to_public_key(&self, private_key: Uint) ->
// PrimeFieldElement<'_> {     self.generator().pow_ct(private_key)
// }

impl<U, V> DiffieHellman for ModPGroup<U, V>
where
    U: UintMont + ConditionallySelectable,
    V: UintMont + UintExp,
{
    /// Generate private key according to PKCS #3.
    /// Generate a value 2^(bits - 1) < 2^bits
    /// TODO: X9.42 (repro in RFC 2631) require [2, (q - 2)]
    fn generate_private_key(&self, rng: &mut dyn CryptoCoreRng) -> Vec<u8> {
        todo!()
    }

    fn private_to_public(&self, private: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    fn shared_secret(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
