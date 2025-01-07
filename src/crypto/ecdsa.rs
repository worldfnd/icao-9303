//! ECDSA signature verification implementation

use {
    super::{
        groups::{EllipticCurve, EllipticCurvePoint},
        mod_ring::{ModRingElementRef, RingRefExt, UintMont},
    },
    crate::asn1::{
        public_key_info::{ECAlgoParameters, FieldId, PubkeyAlgorithmIdentifier},
        DigestAlgorithmIdentifier, DigestAlgorithmParameters, SignatureAlgorithmIdentifier,
    },
    anyhow::{anyhow, bail, ensure, Result},
    der::{Decode, Encode},
    num_traits::Inv,
    ruint::{aliases::U512, Uint},
};

#[derive(Clone, Debug)]
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
        let x = q.x().unwrap();
        let x_scalar = self.curve.scalar_field().from(x.to_uint());

        // Compare with r
        ensure!(x_scalar == *r, "Signature verification failed");

        Ok(())
    }
}

impl<const B: usize, const L: usize> TryFrom<&spki::SubjectPublicKeyInfoOwned>
    for ECPublicKey<Uint<B, L>>
{
    type Error = anyhow::Error;
    fn try_from(spki_pk: &spki::SubjectPublicKeyInfoOwned) -> anyhow::Result<Self, anyhow::Error> {
        let algo = PubkeyAlgorithmIdentifier::from_der(&spki_pk.algorithm.to_der()?)?;
        match algo {
            PubkeyAlgorithmIdentifier::Ec(params) => {
                let point_bytes = spki_pk.subject_public_key.as_bytes().unwrap();
                let curve = match params {
                    ECAlgoParameters::EcParameters(params) => match params.field_id {
                        FieldId::PrimeField { modulus } => {
                            let p = Uint::try_from(modulus)?;
                            let a = Uint::from_be_slice(params.curve.a.as_bytes());
                            let b = Uint::from_be_slice(params.curve.b.as_bytes());
                            let (x, y) = parse_ec_point(params.base.as_bytes())?;
                            let order = Uint::try_from(params.order)?;
                            let cofactor = Uint::try_from(
                                params
                                    .cofactor
                                    .ok_or_else(|| anyhow!("Missing cofactor in EcParameters"))?,
                            )?;

                            EllipticCurve::new(p, a, b, x, y, order, cofactor)?
                        }
                        _ => todo!(),
                    },
                    _ => todo!(),
                };

                let (x, y) = parse_ec_point(point_bytes)?;
                Ok(ECPublicKey {
                    curve,
                    point: (x, y),
                })
            }
            _ => bail!("SubjectPublicKeyInfo not EC-variant"),
        }
    }
}

fn parse_ec_point<const B: usize, const L: usize>(
    octet_string: &[u8],
) -> Result<(Uint<B, L>, Uint<B, L>)> {
    ensure!(
        octet_string[0] == 0x04,
        "Only uncompressed EC point supported, TODO others"
    );

    let coords = &octet_string[1..];
    let (x_bytes, y_bytes) = coords.split_at(coords.len() / 2);

    let x = Uint::from_be_slice(x_bytes);
    let y = Uint::from_be_slice(y_bytes);

    Ok((x, y))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            asn1::{DigestAlgorithmIdentifier, DigestAlgorithmParameters},
            crypto::{groups::named::secp256r1, mod_ring::RingRefExt},
        },
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

        let digest_algo = DigestAlgorithmIdentifier::Sha256(DigestAlgorithmParameters::Null);

        pubkey.verify(&message, &signature, &signature_algo)?;

        Ok(())
    }
}
