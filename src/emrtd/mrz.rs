use {
    super::{Error, Result},
    anyhow::anyhow,
    sha1::{Digest, Sha1},
    std::{
        fmt::{self, Display},
        iter::repeat,
    },
};

#[derive(Clone, Debug)]
pub struct MrzInfo {
    info: String,
}

impl MrzInfo {
    /// Constructs MRZ information from visible document details.
    /// The input document number `docno` can be under padded.
    pub fn from_details(docno: &str, birthdate: &str, expirydate: &str) -> Result<Self> {
        // Validate inputs
        if !Self::has_valid_chars(docno) {
            return Err(Error::InvalidMRZ(anyhow!("Invalid document number")));
        }
        if birthdate.len() != 6 || !Self::has_valid_chars(birthdate) {
            return Err(Error::InvalidMRZ(anyhow!("Invalid birth date")));
        }
        if expirydate.len() != 6 || !Self::has_valid_chars(expirydate) {
            return Err(Error::InvalidMRZ(anyhow!("Invalid expiry date")));
        }

        let mut info = String::new();
        info.push_str(docno);
        if docno.len() < 9 {
            info.extend(repeat('<').take(9 - docno.len()))
        };
        info.push(Self::check_digit(docno));

        info.push_str(birthdate);
        info.push(Self::check_digit(birthdate));

        info.push_str(expirydate);
        info.push(Self::check_digit(expirydate));

        Ok(Self { info })
    }

    pub fn seed(&self) -> [u8; 16] {
        let mut hasher = Sha1::new();
        hasher.update(self.info.as_bytes());
        let hash = hasher.finalize();
        hash[0..16].try_into().unwrap()
    }

    fn check_digit(str: &str) -> char {
        let weights = [7, 3, 1];
        let result = str.chars().enumerate().fold(0, |acc, (i, c)| {
            let digit = Self::char_to_value(c);
            (acc + weights[i % 3] * digit) % 10
        });

        char::from_digit(result as u32, 10).unwrap_or('<')
    }

    fn char_to_value(c: char) -> i32 {
        match c {
            '0'..='9' => c.to_digit(10).unwrap() as i32,
            'A'..='Z' => (c as u8 - b'A' + 10) as i32,
            '<' => 0,
            _ => panic!("Invalid MRZ character"),
        }
    }

    fn has_valid_chars(s: &str) -> bool {
        s.chars().all(|c| matches!(c, '0'..='9' | 'A'..='Z' | '<'))
    }
}

impl Display for MrzInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.info)
    }
}

impl AsRef<str> for MrzInfo {
    fn as_ref(&self) -> &str {
        &self.info
    }
}

impl TryFrom<&str> for MrzInfo {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self> {
        if Self::has_valid_chars(val) {
            Ok(Self { info: val.into() })
        } else {
            Err(Error::InvalidMRZ(anyhow!(
                "MRZ info has invalid characters"
            )))
        }
    }
}

impl TryFrom<String> for MrzInfo {
    type Error = Error;
    fn try_from(val: String) -> Result<Self> {
        Self::try_from(val.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mrz_from_details() {
        let cases = [
            ("L898902C3", "740812", "250415", "L898902C3674081222504155"),
            ("L898902C", "690806", "940623", "L898902C<369080619406236"),
            (
                "D23145890734",
                "340712",
                "950712",
                "D23145890734934071279507122",
            ),
        ];

        for (docno, birth, expiry, expected) in cases {
            let mrz = MrzInfo::from_details(docno, birth, expiry).unwrap();
            assert_eq!(mrz.to_string(), expected);
        }
    }
}
