//! PKI verifications

use {
    crate::{
        asn1::{emrtd::pki::MasterList, SignatureAlgorithmIdentifier},
        crypto::public_key::PublicKey,
    },
    anyhow::{anyhow, ensure, Result},
    cms::{cert::CertificateChoices, content_info::CmsVersion},
    der::Encode,
};

impl MasterList {
    pub fn verify(&self) -> Result<()> {
        let sd = self.signed_data();
        let signer = &sd
            .signer_infos
            .0
            .get(0)
            .ok_or_else(|| anyhow!("SignerInfo must be present"))?;

        // Structure checks, per ICAO 9303-12 9.1
        ensure!(sd.version == CmsVersion::V3);
        ensure!(sd.crls.is_none());

        let certificates = &self
            .signed_data()
            .certificates
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the Certificates field"))?
            .0;

        let master_cert = certificates
            .iter()
            .find_map(|choice| {
                if let CertificateChoices::Certificate(cert) = choice {
                    (cert.tbs_certificate.subject != cert.tbs_certificate.issuer).then(|| cert)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow!("Self-signed certfificate not found in SignedData.certificates")
            })?;
        let master_pubkey = &master_cert.tbs_certificate.subject_public_key_info;
        let pubkey = PublicKey::try_from(master_pubkey)?;

        let attrs = &signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let message = attrs.to_der()?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&signer.signature_algorithm)?;

        let signature = signer.signature.as_bytes();

        pubkey.verify(&message, &signature, &signature_algo)?;

        // let list = self.csca_ml()?;
        // for cert in list.cert_list.iter() {}

        Ok(())
    }
}
