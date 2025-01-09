use {
    anyhow::{anyhow, bail, ensure, Result},
    cms::cert::x509::certificate::{CertificateInner as X509Certificate, Version},
    der::{asn1::ObjectIdentifier as Oid, DateTime, Decode, Encode},
    std::time::SystemTime,
};

const ID_CE_SUBJECTKEYIDENTIFIER: Oid = Oid::new_unwrap("2.5.29.14");

#[derive(Clone, Debug)]
pub enum Certificate<C> {
    CSCA(C),
    CSCALink(C),
    DocumentSigner(C),
    MasterListSigner(C),
    DeviationListSigner(C),
    Communication(C),
}

pub trait X509 {
    fn x509(&self) -> &X509Certificate;
}

impl<C: X509> X509 for Certificate<C> {
    fn x509(&self) -> &X509Certificate {
        match self {
            Self::CSCA(cert) => cert.x509(),
            Self::CSCALink(cert) => cert.x509(),
            Self::DocumentSigner(cert) => cert.x509(),
            Self::MasterListSigner(cert) => cert.x509(),
            Self::DeviationListSigner(cert) => cert.x509(),
            Self::Communication(cert) => cert.x509(),
        }
    }
}

impl X509 for X509Certificate {
    fn x509(&self) -> &X509Certificate {
        self
    }
}

impl X509 for &X509Certificate {
    fn x509(&self) -> &X509Certificate {
        self
    }
}

pub trait EmrtdPKIProfile: X509 {
    fn compliance(&self) -> Result<()>;
}

impl<C: X509> EmrtdPKIProfile for Certificate<C> {
    fn compliance(&self) -> Result<()> {
        let cert = &self.x509().tbs_certificate;

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

        let extensions = if let Some(extensions) = &cert.extensions {
            extensions
        } else {
            bail!("Certificate extensions must be present")
        };

        // Extensions
        // subjectKeyIdentifier
        match self {
            Self::CSCA(cert) | Self::CSCALink(cert) => {
                let extensions = cert.x509().tbs_certificate.extensions.as_ref().unwrap();

                extensions
                    .iter()
                    .find(|ext| ext.extn_id == ID_CE_SUBJECTKEYIDENTIFIER)
                    .ok_or_else(|| {
                        anyhow!("Certificate extensions must include subjectKeyIdentifier")
                    })?;
            }
            _ => (),
        }

        Ok(())
    }
}
