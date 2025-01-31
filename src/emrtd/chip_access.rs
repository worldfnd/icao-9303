//! Chip access procedure to authenticate the inspection system
//! Reference ICAO 9303-11 4.2

use {super::Emrtd, crate::asn1::emrtd::EfCardAccess, anyhow::Result, rand::Rng};

impl Emrtd {
    /// Establish PACE or BAC with the eMRTD chip
    pub fn chip_access(&mut self, rng: &mut impl Rng, mrz: &str) -> Result<()> {
        let file = self.read_cached::<EfCardAccess>();
        match file {
            Ok(access) => {
                let info = access.pace_info()?;
                self.pace(rng, &mrz, info)
            }
            _ => self.basic_access_control(rng, &mrz),
        }
    }
}
