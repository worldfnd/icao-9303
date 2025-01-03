mod dataset;

use {
    anyhow::Result,
    dataset::Dataset,
    der::Decode,
    icao_9303::asn1::emrtd::{pki::MasterList, EfSod},
};

#[test]
fn test_verify_sod() -> Result<()> {
    let dataset = Dataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;

    sod.verify_signature()?;

    Ok(())
}

#[test]
fn test_verify_master_list() -> Result<()> {
    let dataset = Dataset::load()?;
    let ml = MasterList::from_der(&dataset.master_list)?;

    ml.verify()?;

    Ok(())
}
