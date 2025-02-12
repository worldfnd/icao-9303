use super::{groups::ModPGroup, mod_ring::UintMont};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DHPublicKey<U: UintMont, V: UintMont> {
    pub group: ModPGroup<U, V>,
    pub key:   U,
}
