use der::asn1::ObjectIdentifier as Oid;

// https://www.rfc-editor.org/rfc/rfc5114
// https://www.secg.org/sec2-v2.pdf
// Some OIDs are from ANSI X9.62, others from Certicom
pub const ID_SEC_P192R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.1");
pub const ID_SEC_P224R1: Oid = Oid::new_unwrap("1.3.132.0.33");
pub const ID_SEC_P256R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
pub const ID_SEC_P384R1: Oid = Oid::new_unwrap("1.3.132.0.34");
pub const ID_SEC_P521R1: Oid = Oid::new_unwrap("1.3.132.0.35");

// https://www.rfc-editor.org/rfc/rfc5639
pub const ID_BRAINPOOL_P160R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.1");
pub const ID_BRAINPOOL_P192R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.3");
pub const ID_BRAINPOOL_P224R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.5");
pub const ID_BRAINPOOL_P256R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.7");
pub const ID_BRAINPOOL_P320R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.9");
pub const ID_BRAINPOOL_P384R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.11");
pub const ID_BRAINPOOL_P512R1: Oid = Oid::new_unwrap("1.3.36.3.3.2.8.1.1.13");
