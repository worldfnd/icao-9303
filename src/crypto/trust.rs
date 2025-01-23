use {
    super::{
        certificate::{Certificate, ComplianceFailure, EmrtdPKIProfile, X509},
        pki::RevocationStatus,
    },
    crate::asn1::emrtd::pki::{MasterList, CRL},
    anyhow::{anyhow, bail, Result},
    cms::cert::x509::{attr::AttributeTypeAndValue, name::Name},
    std::collections::{hash_map::Entry, HashMap},
};

#[derive(Debug, Clone)]
pub struct TrustStore {
    /// Trusted CSCA certificates, mapped by Subject ID
    certs:  HashMap<CanonicalId, Certificate>,
    /// CRLs, mapped by Issuer ID
    crls:   HashMap<CanonicalId, CRL>,
    /// Validation policy
    policy: TrustPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Strict validation, no deviations allowed
    Strict,
    /// Allow minor deviations that don't impact security
    /// (e.g., missing extensions)
    Relaxed,
    /// Allow most deviations except critical security violations
    /// (e.g., expired certificates, invalid signatures)
    Permissive,
    /// Accept everything except cryptographic failures
    /// (Use with caution, mainly for testing/debugging)
    Testing,
}

/// Canonical RDN, Serial Number
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CanonicalId(String);

impl TrustStore {
    pub fn new(policy: TrustPolicy) -> Self {
        Self {
            certs: HashMap::new(),
            crls: HashMap::new(),
            policy,
        }
    }

    pub fn add_certificate(&mut self, cert: Certificate) -> Result<()> {
        match cert.compliance() {
            Ok(()) => {
                self.insert_certificate(cert)?;
            }
            Err(e) => match self.policy {
                TrustPolicy::Strict => (),
                TrustPolicy::Relaxed => {
                    if !matches!(
                        e,
                        ComplianceFailure::InvalidPeriod(_, _)
                            | ComplianceFailure::ExtensionsAbsent
                    ) {
                        self.insert_certificate(cert)?;
                    }
                }
                TrustPolicy::Permissive => {
                    if !matches!(e, ComplianceFailure::InvalidPeriod(_, _)) {
                        self.insert_certificate(cert)?;
                    }
                }
                TrustPolicy::Testing => {
                    self.insert_certificate(cert)?;
                }
            },
        }
        Ok(())
    }

    fn insert_certificate(&mut self, cert: Certificate) -> Result<()> {
        let id = CanonicalId::of_certificate(&cert)?;
        match self.certs.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(cert);
            }
            // If certificate of same name exists, store the most recent one
            Entry::Occupied(mut entry) => {
                let cert_time = cert
                    .x509()
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration();
                let entry_time = entry
                    .get()
                    .x509()
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration();
                if cert_time > entry_time {
                    entry.insert(cert);
                }
            }
        }
        Ok(())
    }

    pub fn add_crl(&mut self, crl: CRL) -> Result<()> {
        let id = CanonicalId::of_crl(&crl)?;
        self.crls.insert(id, crl);
        Ok(())
    }

    pub fn add_crl_from_distribution_point<C: X509>(&mut self, cert: &C) -> Result<()> {
        let crl = CRL::from_distribution_point(cert)?;
        let id = CanonicalId::of_crl(&crl)?;
        self.crls.insert(id, crl);
        Ok(())
    }

    pub fn add_master_list(&mut self, ml: &MasterList) -> Result<()> {
        for cert in ml.list()?.cert_list.into_vec() {
            self.add_certificate(Certificate::CSCA(cert))?;
        }
        Ok(())
    }

    pub fn verify_certificate<C: X509>(&mut self, cert: &C) -> Result<()> {
        let issuer_id = CanonicalId::of_issuer(cert)?;
        let issuer = self
            .certs
            .get(&issuer_id)
            .ok_or_else(|| anyhow!("Certificate of issuer not found"))?;

        // Verify signature
        issuer.verify(cert)?;

        // Verify revocation status
        // Use CRL from local store, else try to fetch it
        if !self.crls.contains_key(&issuer_id) {
            if let Ok(crl) = CRL::from_distribution_point(issuer) {
                self.add_crl(crl)?;
            }
        }

        // Get CRL, return if not found
        let Some(crl) = self.crls.get(&issuer_id) else {
            return match self.policy {
                TrustPolicy::Strict | TrustPolicy::Relaxed => bail!("CRL not found"),
                _ => Ok(()),
            };
        };

        // Check status
        match (crl.certificate_status(cert), &self.policy) {
            (Ok(()), _) => Ok(()),
            // Lower criticality status
            (
                Err(RevocationStatus::Undetermined(r)),
                TrustPolicy::Strict | TrustPolicy::Relaxed,
            ) => Err(anyhow!(
                "Certificate revocation status is UNDETERMINED: {r}"
            )),
            // Revoked
            (
                Err(RevocationStatus::Unspecified(r)),
                TrustPolicy::Strict | TrustPolicy::Relaxed | TrustPolicy::Permissive,
            ) => Err(anyhow!("Certificate revocation status is UNSPECIFIED: {r}")),
            // Ignore status for other policies
            (Err(_), _) => Ok(()),
        }?;

        Ok(())
    }
}

impl CanonicalId {
    pub fn of_certificate<C: X509>(cert: &C) -> Result<Self> {
        let x509 = cert.x509();
        let name = &x509.tbs_certificate.subject;
        CanonicalId::new(name)
    }

    pub fn of_issuer<C: X509>(cert: &C) -> Result<Self> {
        let x509 = cert.x509();
        let name = &x509.tbs_certificate.issuer;
        CanonicalId::new(name)
    }

    pub fn of_crl(crl: &CRL) -> Result<Self> {
        let name = &crl.0.tbs_cert_list.issuer;
        CanonicalId::new(name)
    }

    pub fn new(name: &Name) -> Result<Self> {
        let mut sets: Vec<&AttributeTypeAndValue> = Vec::new();

        for rdn in &name.0 {
            // Just take the first attribute from each RDN set
            if let Some(first_attr) = rdn.0.get(0) {
                sets.push(first_attr);
            }
        }

        sets.sort_by(|a, b| a.oid.cmp(&b.oid));

        let result: Vec<String> = sets
            .iter()
            .map(|attr| {
                let oid = attr.oid.to_string();
                let name = match oid.as_str() {
                    "2.5.4.3" => "cn",                 // Common Name
                    "2.5.4.6" => "c",                  // Country
                    "2.5.4.7" => "l",                  // Locality
                    "2.5.4.8" => "st",                 // State/Province
                    "2.5.4.10" => "o",                 // Organization
                    "2.5.4.11" => "ou",                // Organizational Unit
                    "1.2.840.113549.1.9.1" => "email", // Email Address
                    "2.5.4.4" => "sn",                 // Surname
                    "2.5.4.42" => "givenName",         // Given Name
                    "2.5.4.12" => "title",             // Title
                    oid => oid,                        // Fall back to OID string for unknown types
                };
                let value = String::from_utf8_lossy(&attr.value.value())
                    .trim()
                    .to_string();
                format!("{}={}", name, value)
            })
            .collect();

        Ok(Self(result.join(",")))
    }
}
