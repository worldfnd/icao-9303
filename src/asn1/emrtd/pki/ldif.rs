//! Basic LDIF parser
//! Only LDIF entries supported

use {
    anyhow::{anyhow, bail, Result},
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    std::collections::HashMap,
};

#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Default)]
pub struct LdifEntry {
    dn:         String,
    attributes: HashMap<String, Vec<AttributeValue>>,
}

impl LdifEntry {
    pub fn new(dn: String) -> Self {
        Self {
            dn,
            attributes: HashMap::new(),
        }
    }

    pub fn add_attribute(&mut self, key: String, value: AttributeValue) {
        self.attributes.entry(key).or_default().push(value);
    }

    pub fn dn(&self) -> &str {
        &self.dn
    }

    pub fn get_attribute(&self, key: &str) -> Option<&Vec<AttributeValue>> {
        self.attributes.get(key)
    }
}

pub fn parse(content: &str) -> Result<Vec<LdifEntry>> {
    let mut entries = Vec::new();
    let mut current_entry: Option<LdifEntry> = None;
    let mut continued_line: Option<String> = None;

    for line in content.lines() {
        let line = line.trim_end(); // Keep leading spaces for continuation detection

        // Skip comments and version header
        if line.trim().starts_with('#') || line.trim().starts_with("version:") {
            continue;
        }

        // Handle line continuation
        if line.starts_with(' ') {
            if let Some(prev) = continued_line.as_mut() {
                if !prev.ends_with(' ') {
                    prev.push(' ');
                }
                prev.push_str(line.trim());
            } else {
                bail!("Continuation line without previous line");
            }
            continue;
        }

        // Process any stored continued line
        if let Some(complete_line) = continued_line.take() {
            process_line(&complete_line, &mut current_entry)?;
        }

        // Skip empty lines between entries
        if line.is_empty() {
            if let Some(entry) = current_entry.take() {
                entries.push(entry);
            }
            continue;
        }

        // Handle backslash continuation
        if line.ends_with('\\') {
            continued_line = Some(line[..line.len() - 1].to_string());
            continue;
        }

        // Store line for potential continuation
        continued_line = Some(line.to_string());
    }

    // Process final continued line if any
    if let Some(complete_line) = continued_line {
        process_line(&complete_line, &mut current_entry)?;
    }

    // Don't forget the last entry
    if let Some(entry) = current_entry {
        entries.push(entry);
    }

    Ok(entries)
}

fn process_line(line: &str, current_entry: &mut Option<LdifEntry>) -> Result<()> {
    if let Some((key, value)) = line.split_once(':') {
        let key = key.trim().to_lowercase();

        // Handle DN (always as text)
        if key == "dn" {
            let dn = if value.starts_with(':') {
                // Base64-encoded DN
                let encoded = value[1..].trim().replace(" ", "");
                String::from_utf8(
                    BASE64
                        .decode(&encoded)
                        .map_err(|e| anyhow!("Invalid base64 in DN: {}", e))?,
                )?
            } else {
                // Regular DN
                value[1..].trim().to_string()
            };
            *current_entry = Some(LdifEntry::new(dn));
        // Handle other attributes
        } else if let Some(entry) = current_entry {
            let attr_value = if value.starts_with(':') {
                // Base64-encoded value
                let encoded = value[1..].trim().replace(" ", "");
                AttributeValue::Binary(
                    BASE64
                        .decode(&encoded)
                        .map_err(|e| anyhow!("Invalid base64 in {}: {}", key, e))?,
                )
            } else {
                // Regular value
                AttributeValue::Text(value[1..].trim().to_string())
            };
            entry.add_attribute(key, attr_value);
        } else {
            bail!("Attribute found before DN: {}", line);
        }
    } else {
        bail!("Invalid LDIF line format: {}", line);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ldif_parsing() {
        let ldif = r#"
dn: cn=John Doe,dc=example,dc=com
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
mail: john@example.com
mail: johndoe@example.com

dn: cn=Jane Smith,dc=example,dc=com
objectClass: inetOrgPerson
cn: Jane Smith
sn: Smith
mail: jane@example.com
"#;

        let entries = parse(ldif).unwrap();
        assert_eq!(entries.len(), 2);

        let john = &entries[0];
        assert_eq!(john.dn(), "cn=John Doe,dc=example,dc=com");
        assert_eq!(john.get_attribute("mail").unwrap().len(), 2);

        let jane = &entries[1];
        assert_eq!(jane.dn(), "cn=Jane Smith,dc=example,dc=com");
        assert_eq!(jane.get_attribute("mail").unwrap().len(), 1);
    }

    #[test]
    fn test_continued_lines() {
        let ldif = r#"
dn: cn=John Doe,dc=example,dc=com
description: This is a very long description that \
 continues on the next line
mail: john@example.com
"#;

        let entries = parse(ldif).unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(
            entry.get_attribute("description").unwrap()[0],
            AttributeValue::Text(
                "This is a very long description that continues on the next line".to_string()
            )
        );
    }

    #[test]
    fn test_invalid_base64() {
        let ldif = r#"dn: cn=John Doe,dc=example,dc=com
jpegPhoto:: !@#$%^&*"#;

        assert!(parse(ldif).is_err());
    }

    #[test]
    fn test_valid_base64() {
        let ldif = r#"dn: cn=John Doe,dc=example,dc=com
jpegPhoto:: YWJjZGVmZ2g="#;

        let entries = parse(ldif).unwrap();
        assert_eq!(entries.len(), 1);

        if let AttributeValue::Binary(bytes) = &entries[0].get_attribute("jpegphoto").unwrap()[0] {
            assert_eq!(bytes, b"abcdefgh");
        } else {
            panic!("Expected binary value");
        }
    }

    #[test]
    fn test_wrapped_base64() {
        let ldif = r#"dn: cn=John Doe,dc=example,dc=com
jpegPhoto:: VGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIHRoYXQgd2lsbCBi
 ZSB3cmFwcGVkIGFjcm9zcyBtdWx0aXBsZSBsaW5lcw=="#;

        let entries = parse(ldif).unwrap();
        assert_eq!(entries.len(), 1);

        if let AttributeValue::Binary(bytes) = &entries[0].get_attribute("jpegphoto").unwrap()[0] {
            assert_eq!(
                String::from_utf8(bytes.clone()).unwrap(),
                "This is a very long base64 string that will be wrapped across multiple lines"
            );
        } else {
            panic!("Expected binary value");
        }
    }
}
