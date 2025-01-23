use {
    super::{ldif, MasterList},
    anyhow::Result,
    der::Decode,
};

/// Parse the ICAO PKD collection of CSCA Master Lists (.ldif file).
/// Downloadable from the [ICAO PKD repository](https://download.pkd.icao.int).
pub fn parse_master_lists(ldif: &str) -> Result<Vec<MasterList>> {
    let entries = ldif::parse(ldif)?;

    let mls = entries
        .iter()
        .filter_map(|entry| {
            entry
                .get_attribute("pkdmasterlistcontent")
                .and_then(|attr| attr.get(0))
                .and_then(|val| match val {
                    ldif::AttributeValue::Binary(der) => MasterList::from_der(&der).ok(),
                    _ => None,
                })
        })
        .collect::<Vec<MasterList>>();

    Ok(mls)
}
