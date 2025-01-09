mod dataset;

use {
    anyhow::Result,
    dataset::{BSIDataset, DEPKI},
    der::Decode,
    icao_9303::{
        asn1::emrtd::{
            pki::{MasterList, CRL},
            EfSod,
        },
        crypto::certificate::{Certificate, X509Certificate},
    },
};

#[test]
fn test_verify_sod() -> Result<()> {
    let dataset = BSIDataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;

    sod.verify_signature()?;

    Ok(())
}

#[test]
fn test_verify_master_list() -> Result<()> {
    let dataset = DEPKI::load()?;
    let ml = MasterList::from_der(&dataset.ml)?;

    ml.verify()?;

    Ok(())
}

#[test]
fn test_verify_crl() -> Result<()> {
    let dataset = DEPKI::load()?;
    let crl = CRL::from_der(&dataset.crl)?;
    let csca = Certificate::CSCA(X509Certificate::from_der(&dataset.csca)?);

    crl.verify(&csca)?;

    Ok(())
}
