mod dataset;

use {
    anyhow::{anyhow as err, bail, ensure, Result},
    cms::content_info::CmsVersion,
    der::Decode,
    icao_9303::asn1::{DigestAlgorithmIdentifier, EfDg14, EfSod, security_info::SecurityInfo},
    dataset::Dataset,
};

#[test]
fn test_decode_dg14() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg14 = EfDg14::from_der(&dataset.dg14)?;

    assert_eq!(dg14.0.0.len(), 3);

    let _chip_auth = dg14.0.iter()
        .find(|sinfo| matches!(sinfo, SecurityInfo::ChipAuthentication(_)))
        .ok_or_else(|| err!("ChipAuthentication SecurityInfo not found"))?;

    let _chip_auth_pub_key = dg14.0.iter()
        .find(|sinfo| matches!(sinfo, SecurityInfo::ChipAuthenticationPublicKey(_)))
        .ok_or_else(|| err!("ChipAuthenticationPublicKey SecurityInfo not found"))?;

    let _terminal_auth_info = dg14.0.iter()
        .find(|sinfo| matches!(sinfo, SecurityInfo::TerminalAuthentication(_)))
        .ok_or_else(|| err!("TerminalAuthentication SecurityInfo not found"))?;

    if let Some((ca, _)) = dg14.chip_authentication() {
        assert_eq!(ca.version, 1);
    } else {
        bail!("EgDg14::chip_authentication should return ChipAuthenticationInfo");
    }

    Ok(())
}

#[test]
fn test_decode_sod() -> Result<()> {
    let dataset = Dataset::load()?;
    let sod = EfSod::from_der(&dataset.sod)?;

    // SecurityObject
    let security_object = sod.lds_security_object()?;
    
    let dgs = [1, 2, 3, 4, 14];
    for dg in dgs {
        security_object.data_group_hash_values.iter()
            .find(|dgh| dgh.data_group_number == dg)
            .ok_or_else(|| err!("DataGroup hash {} not found", dg))?;
    }

    ensure!(matches!(security_object.hash_algorithm, DigestAlgorithmIdentifier::Sha256(_)), "SecurityObject hash algorithm should be SHA256");

    // Signer
    assert_eq!(sod.signer_info().version, CmsVersion::V1);

    Ok(())
}
