//! PKI verifications

use {
    crate::{
        asn1::{
            emrtd::pki::{ExtendedKeyUsage, MasterList},
            SignatureAlgorithmIdentifier,
        },
        crypto::public_key::PublicKey,
    },
    anyhow::{anyhow, ensure, Result},
    cms::{
        cert::{
            x509::certificate::{Certificate, Version},
            CertificateChoices,
        },
        content_info::CmsVersion,
    },
    der::{asn1::ObjectIdentifier as Oid, DateTime, Decode, Encode},
    std::time::SystemTime,
};

const ID_ICAO_CSCAMLSIGKEY: Oid = Oid::new_unwrap("2.23.136.1.1.3");
const ID_CE_EXTKEYUSAGE: Oid = Oid::new_unwrap("2.5.29.37");

pub trait PKIProfile {
    /// Check if `self` is compliant with ICAO 9303-12 7. profiles
    fn compliance(&self) -> Result<()>;
}

impl PKIProfile for Certificate {
    /// Structure checks, per ICAO 9303-12 7., 9.
    fn compliance(&self) -> Result<()> {
        let cert = &self.tbs_certificate;

        ensure!(cert.version == Version::V3);
        ensure!(cert.serial_number.as_bytes().len() <= 20);

        let now = DateTime::from_system_time(SystemTime::now())?;
        let start = cert.validity.not_before.to_date_time();
        let end = cert.validity.not_after.to_date_time();

        ensure!(now >= start, "Certificate not valid yet");
        ensure!(now <= end, "Certificate expired");

        ensure!(
            cert.issuer_unique_id.is_none(),
            "Certificate issuerUniqueId must be absent"
        );
        ensure!(
            cert.subject_unique_id.is_none(),
            "Certificate subjectUniqueId must be absent"
        );
        ensure!(
            cert.extensions.is_some(),
            "Certificate extensions must be present"
        );

        Ok(())
    }
}

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

        // Certificates must be Master List Signer certificate and CSCA certificate
        ensure!(certificates.len() == 2);
        let (mut csca_cert, mut master_cert) = (None, None);
        for choice in certificates.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                cert.compliance()?;
                if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                    csca_cert = Some(cert);
                } else {
                    // ICAO 9303-12 7.1.1.3
                    // OID included in extendedKeyUsage for Master List Signer must be
                    // 2.23.136.1.1.3
                    let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
                        anyhow!("Master List Signer certificate doesn't have extensions")
                    })?;
                    let eku_val = &extensions
                        .iter()
                        .find(|ext| ext.extn_id == ID_CE_EXTKEYUSAGE)
                        .ok_or_else(|| {
                            anyhow!(
                                "extendedKeyUsage extension not found in Master List Signer \
                                 certificate extensions"
                            )
                        })?
                        .extn_value;
                    let oid = ExtendedKeyUsage::from_der(eku_val.as_bytes())?.oid;
                    ensure!(
                        ID_ICAO_CSCAMLSIGKEY == oid,
                        "extendedKeyUsage included-OID in Master List Signer certificate not of \
                         CSCA Master List signing key"
                    );
                    master_cert = Some(cert);
                }
            }
        }
        let csca_cert = csca_cert
            .ok_or_else(|| anyhow!("CSCA certificate not found in SignedData.certificates"))?;
        let master_cert = master_cert.ok_or_else(|| {
            anyhow!("Master List Signer certfificate not found in SignedData.certificates")
        })?;

        let csca_pubkey = PublicKey::try_from(&csca_cert.tbs_certificate.subject_public_key_info)?;
        let master_pubkey =
            PublicKey::try_from(&master_cert.tbs_certificate.subject_public_key_info)?;

        // Verify CSCA certificate (self-signed)
        csca_pubkey.verify(
            &master_cert.tbs_certificate.to_der()?,
            &master_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting Master List certificate signature into bytes")
            })?,
            &SignatureAlgorithmIdentifier::try_from(&master_cert.signature_algorithm)?,
        )?;

        // Verify Master List Signer certificate
        csca_pubkey.verify(
            &master_cert.tbs_certificate.to_der()?,
            &master_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting CSCA certificate signature into bytes")
            })?,
            &SignatureAlgorithmIdentifier::try_from(&master_cert.signature_algorithm)?,
        )?;

        // Verify CSCAs Master List content
        let attrs = &signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let message = attrs.to_der()?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&signer.signature_algorithm)?;

        let signature = signer.signature.as_bytes();

        master_pubkey.verify(&message, &signature, &signature_algo)?;

        let list = self.csca_ml()?;
        for cert in list.cert_list.iter() {
            cert.compliance()?;
        }

        Ok(())
    }
}
