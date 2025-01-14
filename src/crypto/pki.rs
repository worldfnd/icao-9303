//! PKI verifications

use {
    crate::{
        asn1::{
            emrtd::pki::{DeviationList, ExtendedKeyUsage, MasterList, CRL},
            SignatureAlgorithmIdentifier,
        },
        crypto::{
            certificate::{Certificate, EmrtdPKIProfile, X509Certificate, X509},
            public_key::PublicKey,
        },
    },
    anyhow::{anyhow, bail, ensure, Result},
    cms::{
        cert::{
            x509::ext::pkix::{
                name::{DistributionPointName, GeneralName},
                CrlDistributionPoints,
            },
            CertificateChoices,
        },
        content_info::CmsVersion,
        signed_data::SignedData,
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

    pub fn signer_certificate(&self) -> Result<Certificate<&X509Certificate>> {
        let master_cert = list_signer_certificate(&self.signed_data())?;
        Ok(Certificate::MasterListSigner(master_cert))
    }

    pub fn csca_certificate(&self) -> Result<Certificate<&X509Certificate>> {
        let csca_cert = list_csca_certificate(&self.signed_data())?;
        Ok(Certificate::CSCA(csca_cert))
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

    /// Check if provided certificate is revoked.
    /// Ref RFC 5280 6.3
    pub fn certificate_status<C: X509>(&self, cert: &C) -> Result<()> {
        let cert = cert.x509();

        ensure!(
            self.0.tbs_cert_list.issuer.to_der()? == cert.tbs_certificate.issuer.to_der()?,
            "Certificate issuer is different from the CRL issuer"
        );
        let revoked_certs = self.0.tbs_cert_list.revoked_certificates.as_ref();
        let revoked = revoked_certs.and_then(|rcs| {
            // Find if any revoked certificate's Serial Number match that of input cert
            rcs.iter()
                .find(|rc| rc.serial_number == cert.tbs_certificate.serial_number)
        });
        if let Some(rc) = revoked {
            bail!("Certificate was revoked on {}", rc.revocation_date);
        }

        Ok(())
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

    pub fn signer_certificate(&self) -> Result<Certificate<&X509Certificate>> {
        let dev_cert = list_signer_certificate(&self.signed_data())?;
        Ok(Certificate::DeviationListSigner(dev_cert))
    }

    pub fn csca_certificate(&self) -> Result<Certificate<&X509Certificate>> {
        let csca_cert = list_csca_certificate(&self.signed_data())?;
        Ok(Certificate::CSCA(csca_cert))
    }
}

fn list_signer_certificate(sd: &SignedData) -> Result<&X509Certificate> {
    let certificates = &sd.certificates.as_ref().unwrap().0;

    let master_cert = certificates
        .iter()
        .find_map(|choice| match choice {
            CertificateChoices::Certificate(cert)
                if cert.tbs_certificate.subject != cert.tbs_certificate.issuer =>
            {
                Some(cert)
            }
            _ => None,
        })
        .ok_or_else(|| anyhow!("List Signer certificate not found"))?;

    Ok(master_cert)
}

fn list_csca_certificate(sd: &SignedData) -> Result<&X509Certificate> {
    let certificates = &sd.certificates.as_ref().unwrap().0;

    let csca_cert = certificates
        .iter()
        .find_map(|choice| match choice {
            CertificateChoices::Certificate(cert)
                if cert.tbs_certificate.subject == cert.tbs_certificate.issuer =>
            {
                Some(cert)
            }
            _ => None,
        })
        .ok_or_else(|| anyhow!("List CSCA certificate not found"))?;

    Ok(csca_cert)
}

#[cfg(test)]
mod tests {
    use {super::*, anyhow::Result};

    // PKITS test suite
    const GOOD_CA_CRL: &'static str = "308202003081e9020101300d06092a864886f70d01010b05003040310b3009060355040613025553311f301d060355040a1316546573742043657274696669636174657320323031313110300e06035504031307476f6f64204341170d3130303130313038333030305a170d3330313233313038333030305a3044302002010e170d3130303130313038333030305a300c300a0603551d1504030a0101302002010f170d3130303130313038333030315a300c300a0603551d1504030a0101a02f302d301f0603551d23041830168014580184241bbc2b52944a3da510721451f5af3ac9300a0603551d140403020101300d06092a864886f70d01010b050003820101003dbcf30b8a29c3f06ec56a84ecbbc4f68d4ad38b538b3c7c4a9eb941ac03ff7876be5505751c97d8e468ead5da4d83366a0c88103394073e6d1a4a030ded496dc7e5f36f146cc0b9f0810ad9edfefa4e5932d48fa3cfbfe9dc01329eb351ef6bfae1266de3a521a52b96047a05d6e115b608ab4d935f3846865094cd39a4c0e54e79fe2c3d04a8c73747bf55dece1a7ae4e61e85b2058e89ab069fafedca6f6d783b7f2f686539db19b2f5f528f734131507563248501613a28ab2cbf0ae4f314795ae9161562f26e445e6a602c5ad064d92b72260ad2775dfb0675f2c424367b4f5ef10501ee70cbc854b9babd8e38594cbb3ea421649b24849304be3d35644";
    const GOOD_SUBCA_CERT: &'static str = "3082038a30820272a003020102020111300d06092a864886f70d01010b05003040310b3009060355040613025553311f301d060355040a1316546573742043657274696669636174657320323031313110300e06035504031307476f6f64204341301e170d3130303130313038333030305a170d3330313233313038333030305a3043310b3009060355040613025553311f301d060355040a131654657374204365727469666963617465732032303131311330110603550403130a476f6f6420737562434130820122300d06092a864886f70d01010105000382010f003082010a0282010100b20e9896c81423e2717942d0f9e201fb9ef1fdddfdaf3e7395ca9f8f3c64f79fa297e042d68dd5bb0b4823160c48d9a2ff91af06e18bb63034fd72c2bccf469ce37366198150653abe8a2603b5bf585640aa2edc0cd104cd3f44ee8240a224013573d79e09895fc38b1bdc8b30e4e894594ba14be60280c6af2967e368187185dd24ca160aaf899006b1b38b550a5f8e9007cb44cef287f219ae18df790a4c732d357be3a4bb602a7494d04838c306bbc8db5fab0772e78c9bd66e99bb35b24bdf92e639cfe477660fc85c38bc9d2e15d9fde65284b8ce8763f3ed90936bdfafeac09d22c67b573c2c982f20d216a6926bef4b19b709ae9eb2468083e217193b0203010001a3818b308188301f0603551d23041830168014580184241bbc2b52944a3da510721451f5af3ac9301d0603551d0e0416041432072c9e745d2d5d29bbb17a8d3b1552b47d4278300e0603551d0f0101ff04040302010630170603551d200410300e300c060a60864801650302013001300f0603551d130101ff040530030101ff300c0603551d2404053003800100300d06092a864886f70d01010b05000382010100717daf46c1f53b51d0b01ffb2657fea2fe297c8c1f4f93c0beffa9e1ba3ec1672e98f202d438d493cc67390533dd1921432a936c4fb5386b80d5f8ced15259ed87af2a53ba30790c613e0de6681ed99bb1316fb7e68859db70c71071a4d7be1063a57c9782026aedacd7f4916a316a7d1998decf20645a345015f42887265d2bb46077da1d65e7abb6ecf2408e0d6d2a3109e5a6c52d6f07653e7e63b7591b327464acace3aee7a15c69bb8170b64251e01ff31f260a5ac277bf9f40f03c154cb3f295b91fc745a76e9d2b867f9572feb9ba919f0b9eef3eb24de97d65ddc042b6b5602b71552fdf087a8d138e6ac1100b5021dc7d225effc44c2bf706704715";
    const REVOKED_SUBCA_CERT: &'static str = "3082037d30820265a00302010202010e300d06092a864886f70d01010b05003040310b3009060355040613025553311f301d060355040a1316546573742043657274696669636174657320323031313110300e06035504031307476f6f64204341301e170d3130303130313038333030305a170d3330313233313038333030305a3046310b3009060355040613025553311f301d060355040a131654657374204365727469666963617465732032303131311630140603550403130d5265766f6b656420737562434130820122300d06092a864886f70d01010105000382010f003082010a0282010100a518a5a2090c1facc4bd0d54f57cd929625e59b9ad343d81e8bcf9c18eb0c68f04ae21e6ec0ded652adcb663f00f0cb958156f846f5ec924d17286b7b9f3d30ef6338a087cc76a5250cdd5829d46b96e37ea489391674cee4cb15d29a0309eceeaeb548f62f39dbdff5f75d30348fb018dc577d84b6bd25be90ad062ecd1ea9010901e1a88ff0e516eb0fc507072f476c2d0e4e7b2e2d12c78785ea879b0a4777028e4420f95686aa9679645fc7e465e674ae352214abb69cd1ccd0064f94ccb09ced6a3fa9d13c8dcd2fe48af10447173edb9200f5f92af3184e9c680a197139f0702f00249895f0bc357f2a14443e1945bde819e999277836d4135ce281df90203010001a37c307a301f0603551d23041830168014580184241bbc2b52944a3da510721451f5af3ac9301d0603551d0e04160414966f9299a0e97674bb5fd4f8fb19d9cf1d05a0ef300e0603551d0f0101ff04040302010630170603551d200410300e300c060a60864801650302013001300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100877504220bfebd6ec89b9e43b2b304a16a1e3e635be6eac7fbd2f4029ca70045d8fa237344a9504ee3f9c5903648afc22d6d4e107db286939d8d81c408bea97d7563bd0a9c130820b6b601c53b3fd43f96e3836634889688040fd05f4c5cc10b34706e4f5e0705f72c116e875070a2e7a9d7089c103e7ec9454151ee937ae9652ea3b83c0952cfc0901f5106387700fbc27a5be330e6f55b9e32fef5163fc0d426b687ad97a81fab39d544aef5c5e64798d104886b5c3d1982ed930df9ac61563680e1800e8c7d332c782cb8eb7ca90a70a4c71a534e91fc2210bd081fa4e8012836dd597b3c0d34468cffb6a0b62ee56b9eed505669cd190803885aa4b5c97c";

    #[test]
    fn test_crl_revocation() -> Result<()> {
        let crl = CRL::from_der(&hex::decode(GOOD_CA_CRL)?)?;
        let good_cert = X509Certificate::from_der(&hex::decode(GOOD_SUBCA_CERT)?)?;
        let revoked_cert = X509Certificate::from_der(&hex::decode(REVOKED_SUBCA_CERT)?)?;

        crl.certificate_status(&good_cert)?;
        match crl.certificate_status(&revoked_cert) {
            Err(_) => Ok(()),
            Ok(()) => bail!("Revoked certificate not reported as revoked!"),
        }
    }
}
