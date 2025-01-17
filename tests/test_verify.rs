mod dataset;

use {
    anyhow::{bail, Result},
    dataset::{BSIDataset, DEPKI},
    der::Decode,
    icao_9303::{
        asn1::emrtd::{
            pki::{DeviationList, MasterList, CRL},
            EfDg14, EfSod,
        },
        crypto::{
            certificate::{Certificate, X509Certificate},
            signature::SODValidationError,
            TrustStore,
        },
    },
};

#[test]
fn test_verify_sod() -> Result<()> {
    let dataset = BSIDataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;
    // We don't have the CSCA certificate for the BSI dataset
    let store = TrustStore::new();

    match sod.verify_signature(&store) {
        // Should only fail on trust store check
        Err(SODValidationError::TrustFailure(e)) => anyhow::Ok(()),
        _ => bail!("SOD signature verification should fail due to empty TrustStore"),
    }?;

    Ok(())
}

#[test]
fn test_verify_dg14() -> Result<()> {
    let dataset = BSIDataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;
    let dg14 = EfDg14::from_der(&dataset.dg14)?;

    sod.contains_file(&dg14)?;

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

#[test]
fn test_verify_non_revoked() -> Result<()> {
    let dataset = DEPKI::load()?;
    let ml = MasterList::from_der(&dataset.ml)?;
    let crl = CRL::from_der(&dataset.crl)?;

    crl.certificate_status(&ml.signer_certificate()?)?;

    Ok(())
}

#[test]
#[ignore]
fn test_verify_deviation_list() -> Result<()> {
    let dataset = DEPKI::load()?;
    let dvl = DeviationList::from_der(&dataset.dvl)?;

    // DE DVL included certificate expired
    dvl.verify()?;

    Ok(())
}
