use {
    super::{
        ecdsa::{ECPublicKey, ECSignature},
        mod_ring::RingRefExt,
        rsa::RSAPublicKey,
    },
    crate::asn1::{
        public_key_info::SubjectPublicKeyInfo, signature_algorithm_identifier::EcdsaSigValue,
        SignatureAlgorithmIdentifier,
    },
    anyhow::Result,
    der::{Decode, Encode},
    ruint::{aliases::*, Uint},
};

type U521 = Uint<521, 9>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    EC(ECPublicKey<U521>),
    RSA(RSAPublicKey<U4096>),
}

impl PublicKey {
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        signature_algorithm: &SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        match self {
            PublicKey::EC(key) => {
                let EcdsaSigValue { r, s } = EcdsaSigValue::from_der(signature)?;
                let r_elem = key
                    .curve
                    .scalar_field()
                    .from(U521::from_be_slice(&r.as_bytes()));
                let s_elem = key
                    .curve
                    .scalar_field()
                    .from(U521::from_be_slice(&s.as_bytes()));
                let ecsig = ECSignature {
                    r: r_elem,
                    s: s_elem,
                };

                key.verify(message, &ecsig, signature_algorithm)
            }
            PublicKey::RSA(key) => {
                let sigint = U4096::from_be_slice(&signature);
                let rsasig = key.ring.from(sigint);

                key.verify(message, rsasig, signature_algorithm)
            }
        }
    }
}

impl TryFrom<SubjectPublicKeyInfo> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(info: SubjectPublicKeyInfo) -> Result<Self> {
        match info {
            SubjectPublicKeyInfo::RSA(key) => Ok(Self::RSA(key.try_into()?)),
            SubjectPublicKeyInfo::EC(key) => Ok(Self::EC(key.try_into()?)),
            other => todo!(
                "SubjectPublicKeyInfo-variant supported for into-PublicKey conversion: {other:?}"
            ),
        }
    }
}

impl TryFrom<&spki::SubjectPublicKeyInfoOwned> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(info: &spki::SubjectPublicKeyInfoOwned) -> Result<Self> {
        let local_info = SubjectPublicKeyInfo::from_der(&info.to_der()?)?;
        local_info.try_into()
    }
}
