use bytes::Buf;
use std::{
    fmt,
    io::{Cursor, Read},
};

#[derive(Clone, Copy, PartialEq)]
pub struct ElU8(pub u8);
impl fmt::Debug for ElU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}
impl From<ElU8> for usize {
    fn from(value: ElU8) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct ElU16(pub u16);
impl fmt::Debug for ElU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}
impl From<ElU16> for usize {
    fn from(value: ElU16) -> Self {
        value.0.into()
    }
}

const EHD1: u8 = 0x10;
const EHD2: u8 = 0x81;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EOJ([ElU8; 3]);

impl TryFrom<Vec<ElU8>> for EOJ {
    type Error = anyhow::Error;

    fn try_from(value: Vec<ElU8>) -> anyhow::Result<Self> {
        if value.len() != 3 {
            anyhow::bail!("invalid EOJ");
        }
        Ok(Self([value[0], value[1], value[2]]))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Packet {
    pub tid: ElU16, // Transaction ID (2 Bytes)
    pub seoj: EOJ, // Source ECHONET Lite object specification (Class group code 1 Byte, Class code 1 Byte, Instance code 1 Byte)
    pub deoj: EOJ, // Destination ECHONET Lite object specification (Class group code 1 Byte, Class code 1 Byte, Instance code 1 Byte)
    pub esv: ESV,  // ECHONET Lite service (1 Byte)
    pub opc: ElU8, // Number of properties (1 Byte)
    pub props: Vec<Prop>,
}

impl Packet {
    pub fn is_to(&self, eoj: &EOJ) -> bool {
        self.deoj == *eoj
    }

    pub fn is_from(&self, eoj: &EOJ) -> bool {
        self.seoj == *eoj
    }

    pub fn is_normal_response(&self) -> bool {
        match self.esv {
            ESV::SetRes | ESV::GetRes | ESV::SetGetRes => true,
            _ => false,
        }
    }

    pub fn get_prop(&self, epc: ElU8) -> Option<&Prop> {
        self.props.iter().find(|prop| prop.epc == epc)
    }
}

#[derive(Debug, PartialEq)]
pub enum ESV {
    SetI,
    SetC,
    Get,
    InfReq,
    SetGet,
    SetRes,
    GetRes,
    Inf,
    InfC,
    InfCRes,
    SetGetRes,
    SetISNA,
    SetCSNA,
    GetSNA,
    InfSNA,
    SetGetSNA,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Prop {
    pub epc: ElU8, // ECHONET Lite Property code (1 Byte)
    pub pdc: ElU8, // Property data counter (1 Byte)
    pub edt: EDT,  // Property value data (Specified by PDC)
}

#[derive(Debug, PartialEq)]
pub struct EDT(pub Vec<ElU8>);
impl From<Vec<u8>> for EDT {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into_iter().map(ElU8).collect())
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> anyhow::Result<Self> {
        let mut cursor = Cursor::new(value);

        // The minimum length should be 12 bytes (EHD1, EHD2, TID, SEOJ, DEOJ, ESV, OPC)
        if cursor.remaining() < 12 {
            anyhow::bail!("invalid packet");
        }
        if cursor.get_u8() != EHD1 {
            anyhow::bail!("invalid EHD1");
        }
        if cursor.get_u8() != EHD2 {
            anyhow::bail!("invalid EHD2");
        }

        let tid = ElU16(cursor.get_u16());

        let seoj = {
            let mut buf = [0; 3];
            cursor.read_exact(&mut buf)?;
            buf.iter()
                .map(|&x| ElU8(x))
                .collect::<Vec<_>>()
                .try_into()
                .expect("invalid SEOJ")
        };

        let deoj = {
            let mut buf = [0; 3];
            cursor.read_exact(&mut buf)?;
            buf.iter()
                .map(|&x| ElU8(x))
                .collect::<Vec<_>>()
                .try_into()
                .expect("invalid DEOJ")
        };

        let esv = ESV::try_from(cursor.get_u8())?;
        let opc = ElU8(cursor.get_u8());

        let mut props: Vec<Prop> = vec![];
        for _ in 0..usize::from(opc) {
            if cursor.remaining() < 2 {
                anyhow::bail!("invalid property data");
            }
            let epc = ElU8(cursor.get_u8());
            let _pdc = cursor.get_u8();
            if cursor.remaining() < _pdc.into() {
                anyhow::bail!("invalid property data");
            }
            let mut _edt = Vec::with_capacity(_pdc.into());
            for _ in 0.._pdc {
                _edt.push(ElU8(cursor.get_u8()));
            }
            let prop = Prop {
                epc,
                pdc: ElU8(_pdc),
                edt: EDT(_edt),
            };
            props.push(prop);
        }

        Ok(Self {
            tid,
            seoj,
            deoj,
            esv,
            opc,
            props,
        })
    }
}

impl TryFrom<u8> for ESV {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x60 => Ok(Self::SetI),
            0x61 => Ok(Self::SetC),
            0x62 => Ok(Self::Get),
            0x63 => Ok(Self::InfReq),
            0x6E => Ok(Self::SetGet),
            0x71 => Ok(Self::SetRes),
            0x72 => Ok(Self::GetRes),
            0x73 => Ok(Self::Inf),
            0x74 => Ok(Self::InfC),
            0x7A => Ok(Self::InfCRes),
            0x7E => Ok(Self::SetGetRes),
            0x50 => Ok(Self::SetISNA),
            0x51 => Ok(Self::SetCSNA),
            0x52 => Ok(Self::GetSNA),
            0x53 => Ok(Self::InfSNA),
            0x5E => Ok(Self::SetGetSNA),
            _ => anyhow::bail!("invalid ESV"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_packet() {
        {
            let data = [
                0x10, 0x81, // EHD1, EHD1
                0xaa, 0x01, // TID
                0x05, 0xFF, 0x01, // SEOJ
                0x0E, 0xF0, 0x01, // DEOJ
                0x62, // ESV
                0x02, // OPC
                0x82, // EPC1
                0x00, // PDC1
                0x83, // EPC2
                0x00, // PDC2
            ];
            let packet = Packet::try_from(&data[..]).unwrap();
            assert_eq!(packet.tid, ElU16(0xaa01));
            assert_eq!(packet.seoj, EOJ([ElU8(0x05), ElU8(0xff), ElU8(0x01)]));
            assert_eq!(packet.deoj, EOJ([ElU8(0x0e), ElU8(0xf0), ElU8(0x01)]));
            assert_eq!(packet.esv, ESV::Get);
            assert_eq!(packet.opc, ElU8(0x02));
            assert_eq!(packet.props.len(), 2);
            assert_eq!(packet.props[0].epc, ElU8(0x82));
            assert_eq!(packet.props[0].pdc, ElU8(0x00));
            assert_eq!(packet.props[0].edt, EDT(vec![]));
            assert_eq!(packet.props[1].epc, ElU8(0x83));
            assert_eq!(packet.props[1].pdc, ElU8(0x00));
            assert_eq!(packet.props[1].edt, EDT(vec![]));
        }
        {
            let data = [
                0x10, 0x81, // EHD1, EHD1
                0xbb, 0x01, // TID
                0x01, 0x30, 0x01, // SEOJ
                0x05, 0xff, 0x01, // DEOJ
                0x72, // ESV
                0x04, // OPC
                0x82, // EPC1
                0x04, // PDC1
                0x00, 0x00, 0x4a, 0x00, // EDT1
                0x83, // EPC2
                0x11, // PDC2
                0xfe, 0x00, 0x00, 0x08, 0xcc, 0x47, 0x40, 0x21, 0xa6, 0x5b, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, // EDT2
                0x9e, // EPC3
                0x09, // PDC3
                0x08, 0x80, 0x81, 0x8f, 0x93, 0xa0, 0xa3, 0xb0, 0xb3, // EDT3
                0x9f, // EPC4
                0x11, // PDC4
                0x12, 0x0d, 0x01, 0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x08, 0x00,
                0x02, 0x0a, 0x03, // EDT4
            ];
            let packet = Packet::try_from(&data[..]).unwrap();
            assert_eq!(packet.tid, ElU16(0xbb01));
            assert_eq!(packet.seoj, EOJ([ElU8(0x01), ElU8(0x30), ElU8(0x01)]));
            assert_eq!(packet.deoj, EOJ([ElU8(0x05), ElU8(0xff), ElU8(0x01)]));
            assert_eq!(packet.esv, ESV::GetRes);
            assert_eq!(packet.opc, ElU8(0x04));
            assert_eq!(packet.props.len(), 4);
            assert_eq!(packet.props[0].epc, ElU8(0x82));
            assert_eq!(packet.props[0].pdc, ElU8(0x04));
            assert_eq!(packet.props[0].edt, EDT::from(vec![0x00, 0x00, 0x4a, 0x00]));
            assert_eq!(packet.props[1].epc, ElU8(0x83));
            assert_eq!(packet.props[1].pdc, ElU8(0x11));
            assert_eq!(
                packet.props[1].edt,
                EDT::from(vec![
                    0xfe, 0x00, 0x00, 0x08, 0xcc, 0x47, 0x40, 0x21, 0xa6, 0x5b, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00
                ])
            );
            assert_eq!(packet.props[2].epc, ElU8(0x9e));
            assert_eq!(packet.props[2].pdc, ElU8(0x09));
            assert_eq!(
                packet.props[2].edt,
                EDT::from(vec![0x08, 0x80, 0x81, 0x8f, 0x93, 0xa0, 0xa3, 0xb0, 0xb3])
            );
            assert_eq!(packet.props[3].epc, ElU8(0x9f));
            assert_eq!(packet.props[3].pdc, ElU8(0x11));
            assert_eq!(
                packet.props[3].edt,
                EDT::from(vec![
                    0x12, 0x0d, 0x01, 0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x08,
                    0x00, 0x02, 0x0a, 0x03
                ])
            );
        }
    }
}
