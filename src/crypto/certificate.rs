use {
    super::public_key::PublicKey,
    anyhow::{anyhow, bail, ensure, Result},
    cms::cert::x509::{
        certificate::{CertificateInner, Version},
        ext::{pkix::BasicConstraints, Extension},
    },
    der::{asn1::ObjectIdentifier as Oid, DateTime, Decode},
    std::{fmt, time::SystemTime},
};

pub const ID_CE_SUBJECTDIRECTORYATTRIBUTES: Oid = Oid::new_unwrap("2.5.29.9");
pub const ID_CE_SUBJECTKEYIDENTIFIER: Oid = Oid::new_unwrap("2.5.29.14");
pub const ID_CE_KEYUSAGE: Oid = Oid::new_unwrap("2.5.29.15");
pub const ID_CE_PRIVATEKEYUSAGEPERIOD: Oid = Oid::new_unwrap("2.5.29.16");
pub const ID_CE_SUBJECTALTNAME: Oid = Oid::new_unwrap("2.5.29.17");
pub const ID_CE_ISSUERALTNAME: Oid = Oid::new_unwrap("2.5.29.18");
pub const ID_CE_BASICCONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.19");
pub const ID_CE_NAMECONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.30");
pub const ID_CE_CRLDISTRIBUTIONPOINTS: Oid = Oid::new_unwrap("2.5.29.31");
pub const ID_CE_CERTIFICATEPOLICIES: Oid = Oid::new_unwrap("2.5.29.32");
pub const ID_CE_POLICYMAPPINGS: Oid = Oid::new_unwrap("2.5.29.33");
pub const ID_CE_AUTHORITYKEYIDENTIFIER: Oid = Oid::new_unwrap("2.5.29.35");
pub const ID_CE_POLICYCONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.36");
pub const ID_CE_EXTKEYUSAGE: Oid = Oid::new_unwrap("2.5.29.37");
pub const ID_CE_FRESHESTCRL: Oid = Oid::new_unwrap("2.5.29.46");
pub const ID_CE_INHIBITANYPOLICY: Oid = Oid::new_unwrap("2.5.29.54");

pub const ID_NS_NETSCAPECERTIFICATETYPE: Oid = Oid::new_unwrap("2.16.840.1.113730.1.1");

pub const ID_ICAO_EXTENSIONS: Oid = Oid::new_unwrap("2.23.136.1.1.6");
pub const ID_ICAO_EXT_NAMECHANGE: Oid = Oid::new_unwrap("2.23.136.1.1.6.1");
pub const ID_ICAO_EXT_DOCUMENTTYPELIST: Oid = Oid::new_unwrap("2.23.136.1.1.6.2");

#[derive(Clone, Debug)]
pub enum Certificate<C: X509 = X509Certificate> {
    CSCA(C),
    CSCALink(C),
    DocumentSigner(C),
    MasterListSigner(C),
    DeviationListSigner(C),
    Communication(C),
}

pub type X509Certificate = CertificateInner;

/// Helper trait to handle X509 certificates
pub trait X509 {
    /// Fetch the X509 certificate
    fn x509(&self) -> &X509Certificate;
    /// Spawn the certificate's cryptographic subject public key
    fn public_key(&self) -> Result<PublicKey>;
    /// Get an extension, if it exists
    fn extension(&self, oid: &Oid) -> Option<&Extension>;
}

macro_rules! impl_cert_delegate {
    ($method:ident $(($($arg:ident: $type:ty),*))? $(-> $ret:ty)?) => {
        fn $method(&self $($(,$arg: $type)*)?) $(-> $ret)? {
            match self {
                Self::CSCA(cert) => cert.$method($($($arg),*)?),
                Self::CSCALink(cert) => cert.$method($($($arg),*)?),
                Self::DocumentSigner(cert) => cert.$method($($($arg),*)?),
                Self::MasterListSigner(cert) => cert.$method($($($arg),*)?),
                Self::DeviationListSigner(cert) => cert.$method($($($arg),*)?),
                Self::Communication(cert) => cert.$method($($($arg),*)?),
            }
        }
    };
}

impl<C: X509> X509 for Certificate<C> {
    impl_cert_delegate!(x509 -> &X509Certificate);
    impl_cert_delegate!(public_key -> Result<PublicKey>);
    impl_cert_delegate!(extension(oid: &Oid) -> Option<&Extension>);
}

impl<C: X509> fmt::Display for Certificate<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Self::CSCA(_) => "CSCA",
            Self::CSCALink(_) => "CSCA Link",
            Self::DocumentSigner(_) => "Document Signer",
            Self::MasterListSigner(_) => "Master List Signer",
            Self::DeviationListSigner(_) => "Deviation List Signer",
            Self::Communication(_) => "Communication",
        };
        write!(f, "{name} certificate")
    }
}

impl X509 for X509Certificate {
    fn x509(&self) -> &X509Certificate {
        self
    }

    fn public_key(&self) -> Result<PublicKey> {
        PublicKey::try_from(&self.tbs_certificate.subject_public_key_info)
    }

    fn extension(&self, oid: &Oid) -> Option<&Extension> {
        self.tbs_certificate
            .extensions
            .as_ref()
            .and_then(|exts| exts.iter().find(|ext| ext.extn_id == *oid))
    }
}

impl X509 for &X509Certificate {
    fn x509(&self) -> &X509Certificate {
        self
    }

    fn public_key(&self) -> Result<PublicKey> {
        (*self).public_key()
    }

    fn extension(&self, oid: &Oid) -> Option<&Extension> {
        (*self).extension(oid)
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

        ensure!(
            now >= start,
            "Certificate only valid from {}",
            start.to_string()
        );
        ensure!(now <= end, "Certificate expired on {}", end.to_string());

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
        enum Requirement {
            Present,
            Absent,
            Optional,
        }
        let check_ext = |oid: &Oid, req: Requirement| -> Result<()> {
            let present = extensions.iter().any(|ext| ext.extn_id == *oid);
            match (req, present) {
                (Requirement::Present, false) => bail!("Certificate extensions must include {oid}"),
                (Requirement::Absent, true) => {
                    bail!("Certificate extensions must not include {oid}")
                }
                _ => Ok(()),
            }
        };

        // AuthorityKeyIdentifier
        match self {
            Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_AUTHORITYKEYIDENTIFIER, Requirement::Present)?;
            }
            _ => (),
        }

        // SubjectKeyIdentifier
        match self {
            Self::CSCA(_) | Self::CSCALink(_) => {
                check_ext(&ID_CE_SUBJECTKEYIDENTIFIER, Requirement::Present)?;
            }
            _ => (),
        }

        // KeyUsage
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_KEYUSAGE, Requirement::Present)?;
            }
        }

        // PrivateKeyUsagePeriod
        match self {
            Self::CSCA(_) | Self::CSCALink(_) | Self::DocumentSigner(_) => {
                check_ext(&ID_CE_PRIVATEKEYUSAGEPERIOD, Requirement::Present)?;
            }
            _ => (),
        }

        // CertificatePolicies
        match self {
            _ => (),
        }

        // PolicyMappings
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_POLICYMAPPINGS, Requirement::Absent)?;
            }
        }

        // IssuerAltName
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_ISSUERALTNAME, Requirement::Present)?;
            }
        }

        // SubjectAltname
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_SUBJECTALTNAME, Requirement::Present)?;
            }
        }

        // SubjectDirectoryAttributes
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_SUBJECTDIRECTORYATTRIBUTES, Requirement::Absent)?;
            }
        }

        // BasicConstraints
        match self {
            Self::CSCA(cert) | Self::CSCALink(cert) => {
                let ext = cert
                    .extension(&ID_CE_BASICCONSTRAINTS)
                    .ok_or_else(|| anyhow!("{self} extensions must include BasicConstraints"))?;
                let cts = BasicConstraints::from_der(ext.extn_value.as_bytes())?;
                ensure!(
                    cts.ca,
                    "{self} extension BasicConstraints must be labelled as CA"
                );
                ensure!(
                    cts.path_len_constraint.unwrap_or(0) == 0,
                    "{self} extension BasicConstraints path length must be 0"
                );
            }
            Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_BASICCONSTRAINTS, Requirement::Absent)?;
            }
        }

        // NameConstraints
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_NAMECONSTRAINTS, Requirement::Absent)?;
            }
        }

        // PolicyConstraints
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_POLICYCONSTRAINTS, Requirement::Absent)?;
            }
        }

        // ExtKeyUsage
        match self {
            Self::CSCA(_) | Self::CSCALink(_) | Self::DocumentSigner(_) => {
                check_ext(&ID_CE_EXTKEYUSAGE, Requirement::Absent)?;
            }
            Self::MasterListSigner(_) | Self::DeviationListSigner(_) | Self::Communication(_) => {
                check_ext(&ID_CE_EXTKEYUSAGE, Requirement::Present)?;
            }
        }

        // CRLDistributionPoints
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_) => {
                check_ext(&ID_CE_CRLDISTRIBUTIONPOINTS, Requirement::Present)?;
            }
            Self::Communication(_) => {
                check_ext(&ID_CE_CRLDISTRIBUTIONPOINTS, Requirement::Optional)?;
            }
        }

        // InhibitAnyPolicy
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_INHIBITANYPOLICY, Requirement::Absent)?;
            }
        }

        // FreshestCRL
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_CE_FRESHESTCRL, Requirement::Absent)?;
            }
        }

        // NameChange
        match self {
            Self::CSCA(_) | Self::CSCALink(_) => {
                check_ext(&ID_ICAO_EXT_NAMECHANGE, Requirement::Optional)?;
            }
            Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_ICAO_EXT_NAMECHANGE, Requirement::Absent)?;
            }
        }

        // DocumentType
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_ICAO_EXT_DOCUMENTTYPELIST, Requirement::Absent)?;
            }
            Self::DocumentSigner(_) => {
                check_ext(&ID_ICAO_EXT_DOCUMENTTYPELIST, Requirement::Present)?;
            }
        }

        // NetscapeCertificateType
        match self {
            Self::CSCA(_)
            | Self::CSCALink(_)
            | Self::DocumentSigner(_)
            | Self::MasterListSigner(_)
            | Self::DeviationListSigner(_)
            | Self::Communication(_) => {
                check_ext(&ID_NS_NETSCAPECERTIFICATETYPE, Requirement::Absent)?;
            }
        }

        Ok(())
    }
}
