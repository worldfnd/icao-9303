//! PKI verifications

use {
    crate::{
        asn1::{
            emrtd::pki::{DeviationList, ExtendedKeyUsage, MasterList, CRL},
            SignatureAlgorithmIdentifier,
        },
        crypto::{
            certificate::{Certificate, EmrtdPKIProfile, X509},
            public_key::PublicKey,
        },
    },
    anyhow::{anyhow, ensure, Result},
    cms::{
        cert::{
            x509::ext::pkix::{
                name::{DistributionPointName, GeneralName},
                CrlDistributionPoints,
            },
            CertificateChoices,
        },
        content_info::CmsVersion,
    },
    der::{asn1::ObjectIdentifier as Oid, Decode, Encode},
};

const ID_ICAO_CSCAMLSIGKEY: Oid = Oid::new_unwrap("2.23.136.1.1.3");
const ID_ICAO_CSCADLSIGKEY: Oid = Oid::new_unwrap("2.23.136.1.1.8");
const ID_CE_EXTKEYUSAGE: Oid = Oid::new_unwrap("2.5.29.37");

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
                if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                    Certificate::CSCA(cert).compliance()?;
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
                         Master List signing key"
                    );
                    Certificate::MasterListSigner(cert).compliance()?;
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
            &csca_cert.tbs_certificate.to_der()?,
            &csca_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting CSCA certificate signature into bytes")
            })?,
            &SignatureAlgorithmIdentifier::try_from(&csca_cert.signature_algorithm)?,
        )?;

        // Verify Master List Signer certificate
        csca_pubkey.verify(
            &master_cert.tbs_certificate.to_der()?,
            &master_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting Master List certificate signature into bytes")
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

        let list = self.list()?;
        for cert in list.cert_list.iter() {
            // Some certificates are not fully compliant
            // Certificate::CSCA(cert).compliance()?;
        }

        Ok(())
    }
}

impl CRL {
    /// Fetches a CRL from a distribution point.
    /// The distribution point URI must be defined in the provided input `cert`.
    pub fn from_distribution_point(cert: &Certificate) -> Result<Self> {
        let ext = &cert
            .extension(&super::certificate::ID_CE_CRLDISTRIBUTIONPOINTS)
            .ok_or_else(|| {
                anyhow!("Certificate does not contain CrlDistributionPoint extension")
            })?;
        let cdps = CrlDistributionPoints::from_der(ext.extn_value.as_bytes())?;

        let uri = cdps
            .0
            .iter()
            .find_map(|dp| {
                dp.distribution_point.as_ref().and_then(|dpn| match dpn {
                    DistributionPointName::FullName(names) => {
                        for name in names.iter() {
                            match name {
                                GeneralName::UniformResourceIdentifier(s) => {
                                    return Some(s.to_string());
                                }
                                // TODO
                                _ => (),
                            }
                        }
                        None
                    }
                    // TODO
                    DistributionPointName::NameRelativeToCRLIssuer(_) => None,
                })
            })
            .ok_or_else(|| anyhow!("URI not found in CRL distribution points"))?;

        let resp = reqwest::blocking::get(&uri)?.bytes()?;

        Ok(CRL::from_der(&resp)?)
    }

    /// Fetches a country' CRL from the PKD.
    pub fn from_pkd(country_code: &str) -> Result<Self> {
        // Try from link1, then link2 if failed
        let url1 = format!("https://pkddownload1.icao.int/CRLs/{}.crl", country_code);
        let url2 = format!("https://pkddownload2.icao.int/CRLs/{}.crl", country_code);

        let resp = match reqwest::blocking::get(&url1) {
            Ok(resp) => resp.bytes()?,
            Err(_) => reqwest::blocking::get(&url2)?.bytes()?,
        };

        Ok(CRL::from_der(&resp)?)
    }

    pub fn verify<C: X509>(&self, issuer: &Certificate<C>) -> Result<()> {
        let crl = &self.0;

        let message = crl.tbs_cert_list.to_der()?;
        let signature = crl
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("Failed getting signature BIT STRING as bytes"))?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&crl.signature_algorithm)?;

        issuer
            .public_key()?
            .verify(&message, signature, &signature_algo)?;

        Ok(())
    }
}

impl DeviationList {
    pub fn verify(&self) -> Result<()> {
        let sd = self.signed_data();
        let signer = &sd
            .signer_infos
            .0
            .get(0)
            .ok_or_else(|| anyhow!("SignerInfo must be present"))?;

        // Structure checks, per ICAO 9303-12 10.1
        ensure!(sd.version == CmsVersion::V3);
        ensure!(sd.crls.is_none());

        let certificates = &self
            .signed_data()
            .certificates
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the Certificates field"))?
            .0;

        // Certificates must be Deviation List Signer certificate and CSCA certificate
        ensure!(certificates.len() == 2);
        let (mut csca_cert, mut master_cert) = (None, None);
        for choice in certificates.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                    Certificate::CSCA(cert).compliance()?;
                    csca_cert = Some(cert);
                } else {
                    // ICAO 9303-12 7.1.1.3
                    // OID included in extendedKeyUsage for Deviation List Signer must be
                    // 2.23.136.1.1.3
                    let extensions = cert.tbs_certificate.extensions.as_ref().ok_or_else(|| {
                        anyhow!("Deviation List Signer certificate doesn't have extensions")
                    })?;
                    let eku_val = &extensions
                        .iter()
                        .find(|ext| ext.extn_id == ID_CE_EXTKEYUSAGE)
                        .ok_or_else(|| {
                            anyhow!(
                                "extendedKeyUsage extension not found in Deviation List Signer \
                                 certificate extensions"
                            )
                        })?
                        .extn_value;
                    let oid = ExtendedKeyUsage::from_der(eku_val.as_bytes())?.oid;
                    ensure!(
                        ID_ICAO_CSCADLSIGKEY == oid,
                        "extendedKeyUsage included-OID in Deviation List Signer certificate not \
                         of Deviation List signing key"
                    );
                    Certificate::DeviationListSigner(cert).compliance()?;
                    master_cert = Some(cert);
                }
            }
        }
        let csca_cert = csca_cert
            .ok_or_else(|| anyhow!("CSCA certificate not found in SignedData.certificates"))?;
        let deviation_cert = master_cert.ok_or_else(|| {
            anyhow!("Deviation List Signer certfificate not found in SignedData.certificates")
        })?;

        let csca_pubkey = PublicKey::try_from(&csca_cert.tbs_certificate.subject_public_key_info)?;
        let deviation_pubkey =
            PublicKey::try_from(&deviation_cert.tbs_certificate.subject_public_key_info)?;

        // Verify CSCA certificate (self-signed)
        csca_pubkey.verify(
            &csca_cert.tbs_certificate.to_der()?,
            &csca_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting CSCA certificate signature into bytes")
            })?,
            &SignatureAlgorithmIdentifier::try_from(&csca_cert.signature_algorithm)?,
        )?;

        // Verify Deviation List Signer certificate
        csca_pubkey.verify(
            &deviation_cert.tbs_certificate.to_der()?,
            &deviation_cert.signature.as_bytes().ok_or_else(|| {
                anyhow!("Failed converting Deviation List Signer certificate signature into bytes")
            })?,
            &SignatureAlgorithmIdentifier::try_from(&deviation_cert.signature_algorithm)?,
        )?;

        // Verify Deviation List content
        let attrs = &signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let message = attrs.to_der()?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&signer.signature_algorithm)?;

        let signature = signer.signature.as_bytes();

        deviation_pubkey.verify(&message, &signature, &signature_algo)?;

        Ok(())
    }
}
