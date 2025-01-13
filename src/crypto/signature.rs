//! Signature verification for SOD

use {
    crate::{
        asn1::{
            emrtd::EfSod, public_key_info::SubjectPublicKeyInfo, DigestAlgorithmIdentifier,
            SignatureAlgorithmIdentifier,
        },
        crypto::public_key::PublicKey,
        emrtd::{FileId, HasFileId},
    },
    anyhow::{anyhow, ensure, Result},
    cms::{cert::CertificateChoices, content_info::CmsVersion},
    der::{asn1::ObjectIdentifier as Oid, Decode, Encode},
};

const ID_MESSAGEDIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");

impl EfSod {
    /// Check if the provided file is included in the SOD (and is therefore
    /// signed)
    pub fn contains_file<F: HasFileId + Encode>(&self, file: &F) -> Result<()> {
        self.contains_file_bin(&file.to_der()?, F::FILE_ID)
    }

    /// Check if the provided file (as DER bytes) is included in the SOD (and is
    /// therefore signed)
    pub fn contains_file_bin(&self, file: &[u8], id: FileId) -> Result<()> {
        let lds = self.lds_security_object()?;
        let sod_hash = lds
            .data_group_hash_values
            .iter()
            .find(|dgh| dgh.data_group_number == id.short_id() as u64)
            .ok_or_else(|| anyhow!("File {} not included in SOD", id.short_id()))?
            .hash_value
            .as_bytes();
        let file_hash = lds.hash_algorithm.hash_bytes(file);

        ensure!(
            sod_hash == file_hash,
            "Provided file {}'s hash and signed hash do not match",
            id.short_id()
        );

        Ok(())
    }
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
            .ok_or_else(|| anyhow!("Signer certfificate not found in SignedData.certificates"))?;
        let signer_pubkey = &cert.tbs_certificate.subject_public_key_info;

        let pubkey = PublicKey::try_from(SubjectPublicKeyInfo::try_from(signer_pubkey)?)?;

        // Message
        // ICAO 9303-10 4.6.2.2: signedAttrs field is mandatory
        let attrs = &self
            .signer_info()
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("SignedData must contain the signedAttrs field"))?;
        let attrs_der = attrs.to_der()?;

        // Check if signed hash is of LDS
        let lds = self.lds_security_object()?;
        let digest_algo = DigestAlgorithmIdentifier::from_der(
            &self
                .signed_data()
                .digest_algorithms
                .iter()
                .next()
                .ok_or_else(|| anyhow!("SignedData must contain a digest algorithm"))?
                .to_der()?,
        )?;
        let lds_hash = digest_algo.hash_der(&lds);
        let signed_digest = attrs
            .iter()
            .find(|attr| attr.oid == ID_MESSAGEDIGEST)
            .ok_or_else(|| anyhow!("Message digest not found in SignedAttrs"))?
            .values
            .iter()
            .next()
            .ok_or_else(|| anyhow!("SignedAttrs message digest values are empty"))?
            .value();

        ensure!(signed_digest == lds_hash, "Signed hash not of LDS");

        // Signature
        let signature = signer.signature.as_bytes();

        pubkey.verify(&attrs_der, signature, &signature_algo)
    }
}
