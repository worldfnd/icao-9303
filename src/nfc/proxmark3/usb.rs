use {
    super::Connection,
    anyhow::{anyhow, Result},
    rusb::{DeviceHandle, GlobalContext, UsbContext},
    std::time::Duration,
};

const PROXMARK3_VENDOR_ID: u16 = 0x9ac4;
const PROXMARK3_PRODUCT_ID: u16 = 0x4b8f;
const TIMEOUT: Duration = Duration::from_secs(3);

pub struct UsbConnection {
    handle:            DeviceHandle<GlobalContext>,
    bulk_in_endpoint:  u8,
    bulk_out_endpoint: u8,
    buffer:            Vec<u8>,
}

impl UsbConnection {
    pub fn new() -> Result<Self> {
        // Get device handle
        let devices = rusb::devices()?;
        for device in devices.iter() {
            let device_desc = device.device_descriptor()?;
            if device_desc.vendor_id() == PROXMARK3_VENDOR_ID
                && device_desc.product_id() == PROXMARK3_PRODUCT_ID
            {
                return Self::from_device(device);
            }
        }
        panic!("Proxmark3 device not found");
    }

    pub fn from_device(device: rusb::Device<GlobalContext>) -> Result<Self> {
        // let device_descriptor = device.device_descriptor()?;
        // eprintln!("Device descriptor: {:?}", device_descriptor);
        // for i in 0..device_descriptor.num_configurations() {
        //     let config_descriptor = device.config_descriptor(i)?;
        //     eprintln!("Config descriptor {i}: {:?}", config_descriptor);
        //     for interface in config_descriptor.interfaces() {
        //         eprintln!("  Interface: {:?}", interface.number());
        //         for desc in interface.descriptors() {
        //             eprintln!("    Descriptor: {:?}", desc);
        //             for endpoint in desc.endpoint_descriptors() {
        //                 eprintln!("      Endpoint: {:?}", endpoint);
        //             }
        //         }
        //     }
        // }
        let (bulk_in_endpoint, bulk_out_endpoint) = get_endpoints(&device).unwrap();

        let handle = device.open()?;
        handle.claim_interface(1)?;

        // Flush read buffer, local and device
        loop {
            match handle.read_bulk(
                bulk_in_endpoint,
                &mut [0_u8; 64],
                Duration::from_millis(500),
            ) {
                Ok(0) | Err(rusb::Error::Timeout) => break,
                Ok(_) => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(UsbConnection {
            handle,
            bulk_in_endpoint,
            bulk_out_endpoint,
            buffer: Vec::new(),
        })
    }
}

impl Connection for UsbConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.buffer.len() < buf.len() {
            let mut chunk = [0_u8; 64];
            let read = self
                .handle
                .read_bulk(self.bulk_in_endpoint, &mut chunk, TIMEOUT)?;
            assert!(read > 0);
            self.buffer.extend_from_slice(&chunk[..read]);
        }
        buf.copy_from_slice(&self.buffer[..buf.len()]);
        self.buffer.drain(..buf.len());
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        let bytes_written = self
            .handle
            .write_bulk(self.bulk_out_endpoint, data, TIMEOUT)?;
        assert_eq!(bytes_written, data.len());
        // print!("Sent {} bytes:", bytes_written);
        // for byte in data.iter() {
        //     print!(" {:02X}", byte);
        // }
        // println!();
        Ok(())
    }

    fn close(self) -> Result<()> {
        self.handle.release_interface(1)?;
        Ok(())
    }
}

fn get_endpoints<T: UsbContext>(device: &rusb::Device<T>) -> Result<(u8, u8)> {
    let config_desc = device.active_config_descriptor()?;
    let mut bulk_in_endpoint = None;
    let mut bulk_out_endpoint = None;

    for interface in config_desc.interfaces() {
        if interface.number() == 1 {
            for interface_desc in interface.descriptors() {
                for endpoint_desc in interface_desc.endpoint_descriptors() {
                    let addr = endpoint_desc.address();
                    let transfer_type = endpoint_desc.transfer_type();

                    if transfer_type == rusb::TransferType::Bulk {
                        if addr & rusb::constants::LIBUSB_ENDPOINT_IN != 0 {
                            // Bulk IN Endpoint
                            bulk_in_endpoint = Some(addr);
                        } else {
                            // Bulk OUT Endpoint
                            bulk_out_endpoint = Some(addr);
                        }
                    }
                }
            }
        }
    }

    if let (Some(in_ep), Some(out_ep)) = (bulk_in_endpoint, bulk_out_endpoint) {
        Ok((in_ep, out_ep))
    } else {
        Err(anyhow!("Could not find bulk endpoints"))
    }
}
