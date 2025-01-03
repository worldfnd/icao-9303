//! PKI verifications

use {
    crate::{
        asn1::{
            emrtd::{pki::MasterList, EfSod},
            public_key_info::SubjectPublicKeyInfo,
            SignatureAlgorithmIdentifier,
        },
        crypto::{mod_ring::RingRefExt, rsa::RSAPublicKey},
    },
    anyhow::{anyhow, ensure, Result},
    cms::{cert::CertificateChoices, content_info::CmsVersion},
    der::Encode,
    ruint::Uint,
};

impl MasterList {
    pub fn verify(&self) -> Result<()> {
        let sd = self.signed_data();

        // Structure checks, per ICAO 9303-12 9.1
        ensure!(sd.version == CmsVersion::V3);
        ensure!(sd.crls.is_none());

        let certificates = &self
            .signed_data()
            .certificates
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the Certificates field"))?
            .0;

        // Find the self-signed certificate (subject = issuer)
        let master_cert = certificates
            .iter()
            .find_map(|choice| {
                if let CertificateChoices::Certificate(cert) = choice {
                    (cert.tbs_certificate.subject == cert.tbs_certificate.issuer).then(|| cert)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow!("Self-signed certfificate not found in SignedData.certificates")
            })?;
        let master_pubkey = &master_cert.tbs_certificate.subject_public_key_info;

        println!("{:?}", master_cert);

        let list = self.csca_ml()?;
        for cert in list.cert_list.iter() {}

        Ok(())
    }
}
