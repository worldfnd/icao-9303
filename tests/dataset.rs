//! Helper to load BSI TR-03105-5 ReferenceDataSet.
//! Dataset fetched from [here](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip).
#![allow(dead_code)]

use {
    anyhow::Result,
    std::{fs::File, io::Read, path::Path},
};

/// Raw BSI TR-03105-5 ReferenceDataSet.
pub struct Dataset {
    pub dg1:         Vec<u8>,
    pub dg2:         Vec<u8>,
    pub dg3:         Vec<u8>,
    pub dg4:         Vec<u8>,
    pub dg14:        Vec<u8>,
    pub dg15:        Vec<u8>,
    pub com:         Vec<u8>,
    pub sod:         Vec<u8>,
    pub dg14_keys:   Keypair,
    pub dg15_keys:   Keypair,
    pub master_list: Vec<u8>,
}

/// Public-private key pair.
pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

impl Dataset {
    pub fn load() -> Result<Self> {
        let dg1 = Self::read_binfile("tests/dataset/Datagroup1.bin")?;
        let dg2 = Self::read_binfile("tests/dataset/Datagroup2.bin")?;
        let dg3 = Self::read_binfile("tests/dataset/Datagroup3.bin")?;
        let dg4 = Self::read_binfile("tests/dataset/Datagroup4.bin")?;
        let dg14 = Self::read_binfile("tests/dataset/Datagroup14.bin")?;
        let dg15 = Self::read_binfile("tests/dataset/Datagroup15.bin")?;
        let com = Self::read_binfile("tests/dataset/EF_COM.bin")?;
        let sod = Self::read_binfile("tests/dataset/EF_SOD.bin")?;

        let dg14_keys = Keypair {
            pk: Self::read_binfile("tests/dataset/DG14_pk.bin")?,
            sk: Self::read_binfile("tests/dataset/DG14_sk.pkcs8")?,
        };
        let dg15_keys = Keypair {
            pk: Self::read_binfile("tests/dataset/DG15_pk.bin")?,
            sk: Self::read_binfile("tests/dataset/DG15_sk.pkcs8")?,
        };

        let master_list = Self::read_binfile("DE_ML_2024-12-19-10-09-11.ml")?;

        Ok(Self {
            dg1,
            dg2,
            dg3,
            dg4,
            dg14,
            dg15,
            com,
            sod,
            dg14_keys,
            dg15_keys,
            master_list,
        })
    }

    fn read_binfile(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}
