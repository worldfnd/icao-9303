#![allow(clippy::suspicious_arithmetic_impl)]
#![allow(clippy::suspicious_op_assign_impl)]
use {
    num_traits::{Inv, One, Pow, Zero},
    std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// Lowers a multiplicative group to additive operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulGroup<T>(T);

impl<T> MulGroup<T> {
    /// Creates a new multiplicative group element.
    ///
    /// value should be invertible.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the inner value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for MulGroup<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: One + PartialEq> Zero for MulGroup<T> {
    fn zero() -> Self {
        Self(T::one())
    }

    fn is_zero(&self) -> bool {
        self.0.is_one()
    }
}

impl<T: One + PartialEq> Default for MulGroup<T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: Mul<Output = T>> Add for MulGroup<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl<T: MulAssign> AddAssign for MulGroup<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<T: Inv<Output = Option<T>>> Neg for MulGroup<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(self.0.inv().expect("Element is not invertible"))
    }
}

impl<T: Div<Output = Option<T>>> Sub for MulGroup<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.div(rhs.0).expect("Element is not invertible"))
    }
}

impl<T: DivAssign> SubAssign for MulGroup<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 /= rhs.0;
    }
}

impl<T, U> Mul<U> for MulGroup<T>
where
    T: Pow<U, Output = T>,
{
    type Output = Self;

    fn mul(self, rhs: U) -> Self {
        Self(self.0.pow(rhs))
    }
}

impl<T, U> MulAssign<U> for MulGroup<T>
where
    T: Copy + Pow<U, Output = T>,
{
    fn mul_assign(&mut self, rhs: U) {
        self.0 = self.0.pow(rhs);
    }
}

impl<T, U> Div<U> for MulGroup<T>
where
    T: Pow<U, Output = T>,
    U: Inv<Output = Option<U>>,
{
    type Output = Option<Self>;

    fn div(self, rhs: U) -> Self::Output {
        rhs.inv().map(|rhs| self * rhs)
    }
}

impl<T, U> DivAssign<U> for MulGroup<T>
where
    T: Copy + Pow<U, Output = T>,
    U: Inv<Output = Option<U>>,
{
    fn div_assign(&mut self, rhs: U) {
        *self = self.div(rhs).expect("Element is not invertible");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mulgroup() {
        let a = MulGroup::new(3_u64);
        let b = MulGroup::new(4_u64);
        assert_eq!(a + b, 12.into());
        assert_eq!(a * 2_u32, 9.into());
    }
}
