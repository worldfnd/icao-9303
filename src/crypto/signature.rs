//! Signature verification for SOD

use {
    crate::{
        asn1::{
            emrtd::{pki::CscaMasterList, EfSod},
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

impl EfSod {
    /// Verify the signature of the SOD
    pub fn verify_signature(&self) -> Result<()> {
        let signer = self.signer_info();
        let signature_algo = SignatureAlgorithmIdentifier::try_from(&signer.signature_algorithm)?;

        // ICAO 9303-10 4.6.2.2: SignedData must be version 3
        ensure!(
            self.signed_data().version == CmsVersion::V3,
            "SignedData must be version 3"
        );

        // ICAO 9303-10 4.6.2.2: Certificates field is mandatory
        let certificates = &self
            .signed_data()
            .certificates
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the Certificates field"))?
            .0;

        // ICAO 9303-10 4.6.2.2: Crls field must be absent
        ensure!(
            self.signed_data().crls.is_none(),
            "SignedData must not contain the Crls field"
        );

        // Lets just use the first certificate for now, grab the signer public key
        let cert = certificates
            .iter()
            .find_map(|choice| {
                if let CertificateChoices::Certificate(cert) = choice {
                    Some(cert)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("Certificate not found in SignedData.certificates"))?;
        let signer_pubkey = &cert.tbs_certificate.subject_public_key_info;

        type Uint2048 = Uint<2048, 32>;
        let pubkey =
            RSAPublicKey::<Uint2048>::try_from(SubjectPublicKeyInfo::try_from(signer_pubkey)?)?;

        // Message
        // ICAO 9303-10 4.6.2.2: signedAttrs field is mandatory
        let attrs = &self
            .signer_info()
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let attrs_der = attrs.to_der()?;

        // Signature
        let signature = signer.signature.as_bytes();
        let signature_uint = Uint2048::from_be_slice(&signature);
        let signature_elem = pubkey.ring.from(signature_uint);

        pubkey.verify(&attrs_der, signature_elem, &signature_algo)
    }
}
