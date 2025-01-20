use {
    super::certificate::{Certificate, X509},
    crate::asn1::emrtd::pki::{MasterList, CRL},
    anyhow::{anyhow, ensure, Result},
    cms::cert::x509::{attr::AttributeTypeAndValue, name::Name},
    std::collections::HashMap,
};

#[derive(Debug, Clone)]
pub struct TrustStore {
    /// Trusted CSCA certificates, mapped by Subject ID
    certs: HashMap<CanonicalId, Certificate>,
    /// CRLs, mapped by Issuer ID
    crls:  HashMap<CanonicalId, CRL>,
}

/// Canonical RDN, Serial Number
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CanonicalId(String, u64);

impl TrustStore {
    pub fn new() -> Self {
        Self {
            certs: HashMap::new(),
            crls:  HashMap::new(),
        }
    }

    pub fn add_certificate(&mut self, cert: Certificate) -> Result<()> {
        ensure!(
            matches!(Certificate::CSCA, _cert),
            "Only CSCA certificates supported"
        );
        let id = CanonicalId::of_certificate(&cert)?;
        self.certs.insert(id, cert);
        Ok(())
    }

    pub fn add_crl(&mut self, crl: CRL) -> Result<()> {
        let id = CanonicalId::of_crl(&crl)?;
        self.crls.insert(id, crl);
        Ok(())
    }

    pub fn add_master_list(&mut self, ml: &MasterList) -> Result<()> {
        for cert in ml.list()?.cert_list.into_vec() {
            let id = CanonicalId::of_certificate(&cert)?;
            self.certs.insert(id, Certificate::CSCA(cert));
        }
        Ok(())
    }

    pub fn verify_certificate<C: X509>(&self, cert: &C) -> Result<()> {
        let issuer_id = CanonicalId::of_certificate(cert)?;
        let issuer = self
            .certs
            .get(&issuer_id)
            .ok_or_else(|| anyhow!("Certificate of issuer not found"))?;

        // Verify signature
        issuer.verify(cert)?;

        // Verify revocation status
        let issuer_crl = self.crls.get(&issuer_id);
        if let Some(crl) = issuer_crl {
            crl.certificate_status(cert)?;
        }

        Ok(())
    }
}

impl CanonicalId {
    pub fn of_certificate<C: X509>(cert: &C) -> Result<Self> {
        let x509 = cert.x509();
        let name = &x509.tbs_certificate.issuer;
        let sn = x509.serial_number()?;
        CanonicalId::new(name, sn)
    }

    pub fn of_crl(crl: &CRL) -> Result<Self> {
        let name = &crl.0.tbs_cert_list.issuer;
        let at = crl.0.tbs_cert_list.this_update.to_unix_duration().as_secs();
        CanonicalId::new(name, at)
    }

    pub fn new(name: &Name, number: u64) -> Result<Self> {
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

        Ok(Self(result.join(","), number))
    }
}
