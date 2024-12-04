use {
    num_traits::{PrimInt, Unsigned},
    subtle::{Choice, ConstantTimeEq},
};

/// Trait for Uint backends that can be used for exponentiation.
pub trait UintExp {
    /// Returns an upper bound for the highest bit set.
    /// Ideally this should not depend on the value.
    fn bit_len(&self) -> usize;

    /// Is the `indext`th bit set in the binary expansion of `self`.
    fn bit_ct(&self, index: usize) -> Choice;
}

// Implementation that should work for most unsigned integers.
impl<T> UintExp for T
where
    T: PrimInt + Unsigned + ConstantTimeEq,
{
    fn bit_len(&self) -> usize {
        T::zero().count_zeros() as usize
    }

    fn bit_ct(&self, index: usize) -> Choice {
        let bit = T::one() << index;
        (*self & bit).ct_eq(&bit)
    }
}
