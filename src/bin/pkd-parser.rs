#![allow(dead_code)]

use {
    anyhow::Result, argh::FromArgs, icao_9303::asn1::emrtd::pki::pkd::parse_master_lists, std::fs,
};

/// Test a parsing of the ICAO PKD .ldif files.
#[derive(FromArgs)]
struct Args {
    #[argh(positional)]
    master_lists_file: String,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let ldif = fs::read_to_string(args.master_lists_file)?;
    let mls = parse_master_lists(&ldif)?;

    println!("{} CSCA Master Lists in the PKD", mls.len());

    Ok(())
}
