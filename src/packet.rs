use bytes::Buf;
use std::{
    fmt,
    io::{Cursor, Read},
};

#[derive(Clone, Copy)]
pub struct ElU8(u8);
impl fmt::Debug for ElU8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}
impl From<ElU8> for u8 {
    fn from(value: ElU8) -> Self {
        value.0
    }
}
impl From<ElU8> for usize {
    fn from(value: ElU8) -> Self {
        value.0.into()
    }
}

#[derive(Clone, Copy)]
pub struct ElU16(u16);
impl fmt::Debug for ElU16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}", self.0)
    }
}
impl From<ElU16> for u16 {
    fn from(value: ElU16) -> Self {
        value.0
    }
}
impl From<ElU16> for usize {
    fn from(value: ElU16) -> Self {
        value.0.into()
    }
}

const EHD1: u8 = 0x10;
const EHD2: u8 = 0x81;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Packet {
    pub tid: ElU16,      // Transaction ID (2 Bytes)
    pub seoj: [ElU8; 3], // Source ECHONET Lite object specification (Class group code 1 Byte, Class code 1 Byte, Instance code 1 Byte)
    pub deoj: [ElU8; 3], // Destination ECHONET Lite object specification (Class group code 1 Byte, Class code 1 Byte, Instance code 1 Byte)
    pub esv: ESV,        // ECHONET Lite service (1 Byte)
    pub opc: ElU8,       // Number of properties (1 Byte)
    pub props: Vec<Prop>,
}

#[derive(Debug)]
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
    pub epc: ElU8,      // ECHONET Lite Property code (1 Byte)
    pub pdc: ElU8,      // Property data counter (1 Byte)
    pub edt: Vec<ElU8>, // Property value data (Specified by PDC)
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
            let mut edt: Vec<ElU8> = vec![];
            if _pdc > 0 {
                if cursor.remaining() < _pdc.into() {
                    anyhow::bail!("invalid property data");
                }
                let data = cursor.copy_to_bytes(_pdc.into());
                edt = data.to_vec().into_iter().map(ElU8).collect();
            }
            let prop = Prop {
                epc,
                pdc: ElU8(_pdc),
                edt,
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
