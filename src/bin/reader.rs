#![allow(dead_code)]

use {
    anyhow::{anyhow, Context, Result},
    der::Decode,
    icao_9303::{
        asn1::emrtd::{pki::MasterList, EfSod},
        crypto::{TrustPolicy, TrustStore},
        emrtd::{Emrtd, Error, FileId},
        ensure_err,
        iso7816::StatusWord,
        nfc::connect_reader,
    },
    std::{env, fs},
};

// https://github.com/RfidResearchGroup/proxmark3/issues/1117

fn load_truststore() -> Result<TrustStore> {
    // Initialize Trust Store, accepting some CSCA deviations
    let mut store = TrustStore::new(TrustPolicy::Relaxed);

    print!("Setting up trust store with:");
    for entry in fs::read_dir("mls")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            print!(" {}", path.file_name().unwrap().to_string_lossy());
            let ml = MasterList::from_der(&fs::read(&path)?)?;
            store.add_master_list(&ml)?;
        }
    }
    println!();

    Ok(store)
}

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();

    // Find and open the Proxmark3 device
    let mut nfc = connect_reader()?;

    // Connect to ISO 14443-A card as reader, keeping the field on.
    let card = nfc.connect()?;
    ensure_err!(card.is_some(), anyhow!("No card found."));
    dbg!(&card);

    let mut card = Emrtd::new(nfc);

    // println!("=== Basic Access Control.");
    let mrz = env::var("MRZ")?;
    card.basic_access_control(&mut rng, &mrz)
        .context("Error during Basic Access Control.")?;
    eprintln!("Basic Access Control successful.");

    // Verify signature
    let mut store = load_truststore()?;
    let ef_sod = card.read_cached::<EfSod>()?;
    ef_sod.verify_signature(&mut store)?;
    // println!("DOCUMENT HASH = 0x{}", hex::encode(ef_sod.document_hash()));

    // Should be secured now!
    // Let's read some files.
    for file_id in FileId::iter() {
        match card.read_file_cached(file_id) {
            Ok(Some(data)) => {
                let in_sod = ef_sod.contains_file_bin(&data, file_id).is_ok();
                println!(
                    "{} (SOD-authenticated: {in_sod:?}): {}",
                    file_id,
                    hex::encode(data)
                );
            }
            Ok(None) => println!("{}: Not Found", file_id),
            Err(Error::ErrorResponse(StatusWord::ACCESS_DENIED)) => {
                println!("{}: Access Denied", file_id)
            }
            Err(e) => eprintln!("{}: {}", file_id, e),
        }
    }

    // Active Authentication with fixed nonce
    // // ICAO 9303-11 section 6.1
    // eprintln!("=== Active Authentication");
    // let (_status, data) = card.send_apdu(&hex!("00 88 0000  08  00 01 02 03 04 05
    // 06 07  00"))?; println!("==> Active Authentication: {}",
    // hex::encode(data));

    // Dump SOD
    let sod: EfSod = card.read_cached()?;
    println!("DOCUMENT HASH = 0x{}", hex::encode(sod.document_hash()));

    // Do Chip Authentication
    card.chip_authenticate(&mut rng)
        .context("Error during Chip Authentication.")?;

    Ok(())
}
