use der::{self, Decode, Error, ErrorKind, FixedTag, Length, Reader, Tag, TagNumber};

/// EF.DIR is composed of a set of application templates containing the
/// respective IDs. Conditionally required if any optional LDS2 applications are
/// present.
///
/// See ICAO-9303-10 3.11.2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EfDir(Vec<ApplicationTemplate>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationTemplate(ApplicationId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationId(Vec<u8>);

impl EfDir {
    /// Iterator over the application IDs
    pub fn iter(&self) -> impl Iterator<Item = &ApplicationId> {
        self.0.iter().map(|template| &template.0)
    }

    /// Consuming iterator over the application IDs
    pub fn into_iter(self) -> impl Iterator<Item = ApplicationId> {
        self.0.into_iter().map(|template| template.0)
    }
}

impl ApplicationId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FixedTag for ApplicationTemplate {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number:      TagNumber::new(1), // 0x61
    };
}

impl FixedTag for ApplicationId {
    const TAG: Tag = Tag::Application {
        constructed: false,
        number:      TagNumber::new(15), // 0x4f
    };
}

impl<'a> Decode<'a> for ApplicationTemplate {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag = Tag::decode(reader)?;
        if tag != Self::TAG {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        Length::decode(reader)?;
        Ok(Self(ApplicationId::decode(reader)?))
    }
}

impl<'a> Decode<'a> for ApplicationId {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let tag = Tag::decode(reader)?;
        if tag != Self::TAG {
            return Err(Error::new(ErrorKind::TagNumberInvalid, reader.position()));
        };
        let len = Length::decode(reader)?;
        Ok(Self(reader.read_vec(len)?))
    }
}

impl<'a> Decode<'a> for EfDir {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let mut templates = vec![];
        while !reader.remaining_len().is_zero() {
            let template = ApplicationTemplate::decode(reader)?;
            templates.push(template);
        }
        Ok(Self(templates))
    }
}

#[cfg(test)]
mod test {
    use {super::*, hex_literal::hex};

    #[test]
    // ICAO 9303-10 3.11.2
    fn test_decode_efdir_9303p10_t31() {
        let hex = hex!(
            "
            6109 4F07 A0000002471001  
            6109 4F07 A0000002472001  
            6109 4F07 A0000002472002  
            6109 4F07 A0000002472003  
        "
        );

        let efdir = EfDir::from_der(&hex).unwrap();
        assert_eq!(efdir.0.len(), 4);
        assert_eq!(
            efdir.iter().last().unwrap().as_bytes(),
            &hex!("A0000002472003")
        );
    }
}
