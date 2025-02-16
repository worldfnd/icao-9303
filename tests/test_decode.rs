mod dataset;

use {
    anyhow::{anyhow as err, bail, ensure, Result},
    cms::content_info::CmsVersion,
    dataset::Dataset,
    der::Decode,
    hex_literal::hex,
    icao_9303::asn1::{
        emrtd::{
            biometric::Side, security_info::SecurityInfo, EfDg1, EfDg14, EfDg2, EfDg3, EfDg4,
            EfSod, Finger,
        },
        DigestAlgorithmIdentifier,
    },
};

#[test]
fn test_decode_dg1() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg1 = EfDg1::from_der(&dataset.dg1)?;
    let mrz = dg1.data()?;
    assert_eq!(mrz.secondary_identifier, "ERIKA");
    assert_eq!(mrz.date_of_birth, "960812");
    assert_eq!(mrz.date_of_expiry, "231031");
    Ok(())
}

#[test]
fn test_decode_dg2() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg2 = EfDg2::from_der(&dataset.dg2)?;
    let info = &dg2.infos()[0];
    assert_eq!(info.header.btype.as_ref().unwrap().as_bytes(), &hex!("02"));
    assert_eq!(info.header.format_owner.as_bytes(), &hex!("01 01"));
    assert_eq!(info.header.format_type.as_bytes(), &hex!("00 08"));
    Ok(())
}

#[test]
fn test_decode_dg3() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg3 = EfDg3::from_der(&dataset.dg3)?;
    let right = &dg3.infos()[0];
    assert_eq!(right.header.btype.as_ref().unwrap().as_bytes(), &hex!("08"));
    assert_eq!(right.header.format_owner.as_bytes(), &hex!("01 01"));
    assert_eq!(right.finger().side, Side::Right);
    assert_eq!(right.finger().finger, Finger::Pointer);
    let left = &dg3.infos()[1];
    assert_eq!(left.header.btype.as_ref().unwrap().as_bytes(), &hex!("08"));
    assert_eq!(left.header.format_owner.as_bytes(), &hex!("01 01"));
    assert_eq!(left.finger().side, Side::Left);
    assert_eq!(left.finger().finger, Finger::Pointer);
    Ok(())
}

#[test]
fn test_decode_dg4() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg4 = EfDg4::from_der(&dataset.dg4)?;
    let right = &dg4.infos()[0];
    assert_eq!(right.header.btype.as_ref().unwrap().as_bytes(), &hex!("10"));
    assert_eq!(right.header.format_owner.as_bytes(), &hex!("01 01"));
    assert_eq!(right.iris().side, Side::Right);
    let left = &dg4.infos()[1];
    assert_eq!(left.header.btype.as_ref().unwrap().as_bytes(), &hex!("10"));
    assert_eq!(left.header.format_owner.as_bytes(), &hex!("01 01"));
    assert_eq!(left.iris().side, Side::Left);
    Ok(())
}

#[test]
fn test_decode_dg14() -> Result<()> {
    let dataset = Dataset::load()?;
    let dg14 = EfDg14::from_der(&dataset.dg14)?;

    assert_eq!(dg14.0 .0.len(), 3);

    let _chip_auth = dg14
        .0
        .iter()
        .find(|sinfo| matches!(sinfo, SecurityInfo::ChipAuthentication(_)))
        .ok_or_else(|| err!("ChipAuthentication SecurityInfo not found"))?;

    let _chip_auth_pub_key = dg14
        .0
        .iter()
        .find(|sinfo| matches!(sinfo, SecurityInfo::ChipAuthenticationPublicKey(_)))
        .ok_or_else(|| err!("ChipAuthenticationPublicKey SecurityInfo not found"))?;

    let _terminal_auth_info = dg14
        .0
        .iter()
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
        security_object
            .data_group_hash_values
            .iter()
            .find(|dgh| dgh.data_group_number == dg)
            .ok_or_else(|| err!("DataGroup hash {} not found", dg))?;
    }

    ensure!(
        matches!(
            security_object.hash_algorithm,
            DigestAlgorithmIdentifier::Sha256(_)
        ),
        "SecurityObject hash algorithm should be SHA256"
    );

    // Signer
    assert_eq!(sod.signer_info().version, CmsVersion::V1);

    Ok(())
}
