//! ECDSA signature verification implementation

use {
    super::{
        codec::parse_ec_point,
        groups::{EllipticCurve, EllipticCurvePoint},
        mod_ring::{ModRingElementRef, RingRefExt, UintMont},
    },
    crate::asn1::{
        public_key_info::{ECAlgoParameters, EcPublicKeyInfo},
        DigestAlgorithmIdentifier, DigestAlgorithmParameters, SignatureAlgorithmIdentifier,
    },
    anyhow::{anyhow, bail, ensure, Result},
    num_traits::Inv,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECPublicKey<U: UintMont> {
    pub curve: EllipticCurve<U>,
    pub point: (U, U),
}

#[derive(Debug, Clone)]
pub struct ECSignature<'a, U: UintMont> {
    pub r: ModRingElementRef<'a, U>,
    pub s: ModRingElementRef<'a, U>,
}

impl<U: UintMont> ECPublicKey<U> {
    pub fn point(&self) -> Result<EllipticCurvePoint<'_, U>> {
        let base_field = self.curve.base_field();
        let x = base_field.from(self.point.0);
        let y = base_field.from(self.point.1);
        self.curve.from_affine(x, y)
    }

    pub fn verify<'c>(
        &'c self,
        message: &[u8],
        signature: &ECSignature<'c, U>,
        algorithm: &'c SignatureAlgorithmIdentifier,
    ) -> Result<()> {
        let point = self.point()?;
        let ECSignature { r, s } = signature;

        let digest_algo = match algorithm {
            SignatureAlgorithmIdentifier::EcdsaSha1 => {
                DigestAlgorithmIdentifier::Sha1(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::EcdsaSha224 => {
                DigestAlgorithmIdentifier::Sha224(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::EcdsaSha256 => {
                DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::EcdsaSha384 => {
                DigestAlgorithmIdentifier::Sha384(DigestAlgorithmParameters::Null)
            }
            SignatureAlgorithmIdentifier::EcdsaSha512 => {
                DigestAlgorithmIdentifier::Sha512(DigestAlgorithmParameters::Null)
            }
            other => bail!("Unrecognized ECDSA signature algorithm: {other:?}"),
        };
        let hash = digest_algo.hash_bytes(&message);
        let hash_elem = self.curve.scalar_field().from(U::from_be_bytes(&hash));

        // w = s^(-1) mod n
        let w = s.inv().ok_or_else(|| anyhow!("Invalid s value"))?;

        // u1 = e * w mod n
        let u1 = hash_elem * w;

        // u2 = r * w mod n
        let u2 = *r * w;

        // Q = u1*G + u2*Q
        let q = point.curve().generator() * u1 + point * u2;

        // Get x coordinate
        let x = q.x().ok_or_else(|| anyhow!("Failed getting Qx"))?;
        let x_scalar = self.curve.scalar_field().from(x.to_uint());

        // Compare with r
        ensure!(x_scalar == *r, "Signature verification failed (Qx != r)");

        Ok(())
    }
}

impl<U: UintMont> TryFrom<(ECAlgoParameters, EcPublicKeyInfo)> for ECPublicKey<U> {
    type Error = anyhow::Error;

    fn try_from(info: (ECAlgoParameters, EcPublicKeyInfo)) -> Result<Self> {
        let (params, key) = info;
        let point_bytes = key.point.as_bytes();
        let curve = EllipticCurve::from_parameters(params)?;

        let (x, y) = parse_ec_point(&curve, point_bytes)?;
        Ok(Self {
            curve,
            point: (x, y),
        })
    }
}

impl<'a, U: UintMont> From<EllipticCurvePoint<'a, U>> for ECPublicKey<U> {
    fn from(point: EllipticCurvePoint<U>) -> Self {
        ECPublicKey {
            curve: point.curve().clone(),
            point: (point.x().unwrap().to_uint(), point.y().unwrap().to_uint()),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::crypto::{groups::named::secp256r1, mod_ring::RingRefExt},
        anyhow::Result,
        hex_literal::hex,
        ruint::aliases::U256,
    };

    #[test]
    fn test_ecda_nist_p256_sha256() -> Result<()> {
        // RFC 6979 A.2.5
        let curve = secp256r1();
        let message = hex!("73616D706C65"); // "sample"
        let u_x = hex!("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        let u_y = hex!("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        let r = hex!("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let s = hex!("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

        let pubkey = ECPublicKey {
            curve,
            point: (U256::from_be_slice(&u_x), U256::from_be_slice(&u_y)),
        };

        let signature = ECSignature {
            r: curve.scalar_field().from(U256::from_be_slice(&r)),
            s: curve.scalar_field().from(U256::from_be_slice(&s)),
        };

        let signature_algo = SignatureAlgorithmIdentifier::EcdsaSha256;

        pubkey.verify(&message, &signature, &signature_algo)?;

        Ok(())
    }
}
