use {
    super::public_key::PublicKey,
    crate::asn1::SignatureAlgorithmIdentifier,
    anyhow::{anyhow, bail, ensure, Result},
    cms::cert::x509::{
        certificate::{CertificateInner, Version},
        ext::{pkix::BasicConstraints, Extension},
    },
    der::{asn1::ObjectIdentifier as Oid, DateTime, Decode, Encode},
    ruint::aliases::U160,
    std::{fmt, time::SystemTime},
    thiserror::Error,
};

pub const ID_CE_SUBJECTDIRECTORYATTRIBUTES: Oid = Oid::new_unwrap("2.5.29.9");
pub const ID_CE_SUBJECTKEYIDENTIFIER: Oid = Oid::new_unwrap("2.5.29.14");
pub const ID_CE_KEYUSAGE: Oid = Oid::new_unwrap("2.5.29.15");
pub const ID_CE_PRIVATEKEYUSAGEPERIOD: Oid = Oid::new_unwrap("2.5.29.16");
pub const ID_CE_SUBJECTALTNAME: Oid = Oid::new_unwrap("2.5.29.17");
pub const ID_CE_ISSUERALTNAME: Oid = Oid::new_unwrap("2.5.29.18");
pub const ID_CE_BASICCONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.19");
pub const ID_CE_CERTIFICATEISSUER: Oid = Oid::new_unwrap("2.5.29.29");
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
pub enum CertificateProfile<C: X509 = X509Certificate> {
    CSCA(C),
    CSCALink(C),
    DocumentSigner(C),
    MasterListSigner(C),
    DeviationListSigner(C),
    Communication(C),
}

pub type X509Certificate = CertificateInner;

pub type Certificate = CertificateProfile<X509Certificate>;
pub type CertificateRef<'a> = CertificateProfile<&'a X509Certificate>;

/// Helper trait to handle X509 certificates
pub trait X509 {
    /// Fetch the X509 certificate
    fn x509(&self) -> &X509Certificate;
    /// Spawn the certificate's cryptographic subject public key
    fn public_key(&self) -> Result<PublicKey>;
    /// Get an extension, if it exists
    fn extension(&self, oid: &Oid) -> Option<&Extension>;
    /// Get the serial number as an integer
    /// Must be representable using 20 bytes (RFC 5280)
    fn serial_number(&self) -> Result<U160>;
    /// Check if `self` signed input certificate
    fn verify(&self, signed: &impl X509) -> Result<()>;
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

impl<C: X509> X509 for CertificateProfile<C> {
    impl_cert_delegate!(x509 -> &X509Certificate);
    impl_cert_delegate!(public_key -> Result<PublicKey>);
    impl_cert_delegate!(extension(oid: &Oid) -> Option<&Extension>);
    impl_cert_delegate!(serial_number -> Result<U160>);
    impl_cert_delegate!(verify(signed: &impl X509) -> Result<()>);
}

impl<C: X509> fmt::Display for CertificateProfile<C> {
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

    fn serial_number(&self) -> Result<U160> {
        let slice = &self.tbs_certificate.serial_number.as_bytes();
        ensure!(
            slice.len() <= 20,
            "Serial Number not representable in 20 octets"
        );
        Ok(U160::from_be_slice(slice))
    }

    fn verify(&self, signed: &impl X509) -> Result<()> {
        let x509 = signed.x509();
        let message = x509.tbs_certificate.to_der()?;
        let signature = x509
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("Failed getting signature BIT STRING as bytes"))?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&x509.signature_algorithm)?;

        self.public_key()?
            .verify(&message, signature, &signature_algo)
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

    fn serial_number(&self) -> Result<U160> {
        (*self).serial_number()
    }

    fn verify(&self, signed: &impl X509) -> Result<()> {
        (*self).verify(signed)
    }
}

impl<'a> CertificateRef<'a> {
    pub fn into_owned(&self) -> Certificate {
        match self {
            Self::CSCA(cert) => Certificate::CSCA((*cert).clone()),
            Self::CSCALink(cert) => Certificate::CSCALink((*cert).clone()),
            Self::DocumentSigner(cert) => Certificate::DocumentSigner((*cert).clone()),
            Self::MasterListSigner(cert) => Certificate::MasterListSigner((*cert).clone()),
            Self::DeviationListSigner(cert) => Certificate::DeviationListSigner((*cert).clone()),
            Self::Communication(cert) => Certificate::Communication((*cert).clone()),
        }
    }
}

pub trait EmrtdPKIProfile: X509 {
    fn compliance(&self) -> Result<(), ComplianceFailure>;
}

#[derive(Debug, Error)]
pub enum ComplianceFailure {
    #[error("Certificate valid from {0} to {1}")]
    InvalidPeriod(DateTime, DateTime),

    #[error("Extensions are absent")]
    ExtensionsAbsent,

    #[error("Certificate extension {0} not found")]
    ExtensionMissing(Oid),

    #[error("Certificate extension {0} found")]
    ExtensionPresent(Oid),

    #[error("Certificate extension {0} has incorrect attribute: {1}")]
    ExtensionAttributeIncorrect(Oid, &'static str),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl<C: X509> EmrtdPKIProfile for CertificateProfile<C> {
    fn compliance(&self) -> Result<(), ComplianceFailure> {
        let cert = &self.x509().tbs_certificate;

        let now = DateTime::from_system_time(SystemTime::now()).map_err(|e| anyhow!("{e}"))?;
        let start = cert.validity.not_before.to_date_time();
        let end = cert.validity.not_after.to_date_time();

        if now < start || now > end {
            return Err(ComplianceFailure::InvalidPeriod(start, end));
        }

        if cert.issuer_unique_id.is_some() {
            return Err(anyhow!("Certificate issuerUniqueId must be absent").into());
        }

        if cert.subject_unique_id.is_some() {
            return Err(anyhow!("Certificate subjectUniqueId must be absent").into());
        }

        let extensions = cert
            .extensions
            .as_ref()
            .ok_or_else(|| ComplianceFailure::ExtensionsAbsent)?;

        if cert.version != Version::V3 {
            return Err(anyhow!("Version is {:?} (!= 3)", cert.version).into());
        }

        if cert.serial_number.as_bytes().len() > 20 {
            return Err(anyhow!("Serial number larger than 20 bytes").into());
        }

        // Extensions
        enum Requirement {
            Present,
            Absent,
            Optional,
        }
        let check_ext = |oid: &Oid, req: Requirement| -> Result<(), ComplianceFailure> {
            let present = extensions.iter().any(|ext| ext.extn_id == *oid);
            match (req, present) {
                (Requirement::Present, false) => {
                    Err(ComplianceFailure::ExtensionMissing(oid.clone()))
                }
                (Requirement::Absent, true) => {
                    Err(ComplianceFailure::ExtensionPresent(oid.clone()))
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
            Self::CSCA(_) | Self::CSCALink(_) => {
                let ext = self
                    .extension(&ID_CE_BASICCONSTRAINTS)
                    .ok_or_else(|| anyhow!("{self} extensions must include BasicConstraints"))?;
                let cts = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|_| {
                    ComplianceFailure::ExtensionAttributeIncorrect(
                        ID_CE_BASICCONSTRAINTS,
                        "Failed decoding attributes",
                    )
                })?;
                if !cts.ca {
                    return Err(ComplianceFailure::ExtensionAttributeIncorrect(
                        ID_CE_BASICCONSTRAINTS,
                        "Must be labelled as CA",
                    ));
                }
                if cts.path_len_constraint.unwrap_or(0) != 0 {
                    return Err(ComplianceFailure::ExtensionAttributeIncorrect(
                        ID_CE_BASICCONSTRAINTS,
                        "Path length must be 0",
                    ));
                }
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
