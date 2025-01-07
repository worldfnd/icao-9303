//! PKI verifications

use {
    crate::{
        asn1::{
            emrtd::pki::MasterList, signature_algorithm_identifier::EcdsaSigValue,
            DigestAlgorithmIdentifier, DigestAlgorithmParameters, SignatureAlgorithmIdentifier,
        },
        crypto::{
            ecdsa::{ECPublicKey, ECSignature},
            mod_ring::RingRefExt,
        },
    },
    anyhow::{anyhow, ensure, Result},
    cms::{cert::CertificateChoices, content_info::CmsVersion},
    der::{Decode, Encode},
    ruint::aliases::U512,
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
        let pubkey = ECPublicKey::<U512>::try_from(master_pubkey)?;

        let signer = &sd.signer_infos.0.get(0).unwrap();
        let attrs = &signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let attrs_der = attrs.to_der()?;
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&signer.signature_algorithm)?;
        let digest_algo = DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Null);
        let message = digest_algo.hash_bytes(&attrs_der);

        let signature = signer.signature.as_bytes();
        let EcdsaSigValue { r, s } = EcdsaSigValue::from_der(&signature)?;

        let r_elem = pubkey
            .curve
            .scalar_field()
            .from(U512::from_be_slice(&r.as_bytes()));
        let s_elem = pubkey
            .curve
            .scalar_field()
            .from(U512::from_be_slice(&s.as_bytes()));

        let signature = ECSignature {
            r: r_elem,
            s: s_elem,
        };

        pubkey.verify(&attrs_der, &signature, &signature_algo)?;

        // let list = self.csca_ml()?;
        // for cert in list.cert_list.iter() {}

        Ok(())
    }
}
