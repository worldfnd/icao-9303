#![allow(dead_code)]

use {
    anyhow::{anyhow, Result},
    argh::FromArgs,
    der::Decode,
    glob::{glob, Pattern},
    hex_literal::hex,
    icao_9303::{asn1::emrtd::EfDg14, emrtd::secure_messaging::construct_secure_messaging},
};

/// Test a parsing of exported eMRTD documents.
#[derive(FromArgs)]
struct Args {
    /// glob pattern for eMRTD documents as JSON/base64
    #[argh(positional)]
    documents: Pattern,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    for entry in glob(args.documents.as_str())? {
        let path = entry?;
        println!("{:?}", path);
        let dg14 = std::fs::read(path)?;

        let dg14 = hex!("6e2f312d3012060a04007f0007020204020402010202010f30170606678108010105020101060a04007f00070101040104");

        println!("{}", hex::encode(&dg14));
        let dg14 = EfDg14::from_der(&dg14)?;
        for entry in dg14.0.iter() {
            println!(" - DG14: {} {:?}", entry.protocol_name(), entry);
        }
        if let Some((ca, capk)) = dg14.chip_authentication() {
            println!(" - CA: {}", ca.protocol);
            assert_eq!(ca.version, 1);

            // Construct elliptic curve and document public key point.
            let (algo, doc_public_key) = capk.public_key.to_algorithm_public_key()?;
            println!("   - Algorithm: {algo}");
            println!("   - Card Public Key: {}", hex::encode(&doc_public_key));

            // Generate keypair
            let mut rng = rand::thread_rng();
            let (private_key, public_key) = algo.generate_key_pair(&mut rng);
            // println!("   - Private key: {:x}", private_key);
            println!("   - Public key: {}", hex::encode(&public_key));

            // Compute shared secret
            let shared_secret = algo.key_agreement(&private_key, &doc_public_key)?;
            println!("   - Shared secret: {}", hex::encode(&shared_secret));

            // Construct secure messaging cipher and test messages
            const SELECT_MASTER_FILE: &[u8] = &hex!("00A4 000C 02 3F00");
            let cipher = ca
                .protocol
                .cipher
                .ok_or_else(|| anyhow!("No symmetric cipher"))?;
            for i in 0..3 {
                let mut sm = construct_secure_messaging(cipher, &shared_secret, 2 * i);
                let msg = sm.enc_apdu(SELECT_MASTER_FILE)?;
                println!("   - Challenge {}: {}", i, hex::encode(msg));
            }
        }
    }
    Ok(())
}
