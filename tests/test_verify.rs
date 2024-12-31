mod dataset;

use {anyhow::Result, dataset::Dataset, der::Decode, icao_9303::asn1::emrtd::EfSod};

#[test]
fn test_verify() -> Result<()> {
    let dataset = Dataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;

    sod.verify_signature()?;

    Ok(())
}
