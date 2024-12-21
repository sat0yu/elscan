use crate::packet::{ElU8, Packet, EDT, EOJ};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryResponse {
    pub eoj: EOJ,
    pub instances: Vec<EOJ>,
}

impl TryFrom<&Packet> for DiscoveryResponse {
    type Error = anyhow::Error;

    fn try_from(p: &Packet) -> anyhow::Result<Self> {
        if !p.is_normal_response() {
            anyhow::bail!("not a response");
        }
        let controller = EOJ::try_from(vec![ElU8(0x05), ElU8(0xFF), ElU8(0x01)]).unwrap();
        if !p.is_to(&controller) {
            anyhow::bail!("invalid DEOJ");
        }
        let node_profile = EOJ::try_from(vec![ElU8(0x0E), ElU8(0xF0), ElU8(0x01)]).unwrap();
        if !p.is_from(&node_profile) {
            anyhow::bail!("invalid SEOJ");
        }
        let Some(prop) = p.get_prop(ElU8(0xD6)) else {
            anyhow::bail!("not found instance list property");
        };
        // the first byte shows the number of instances(EOJs) and 3-byte chunks in the rest bytes represent instances
        let mut instances = Vec::with_capacity(prop.edt.0[0].0.into());
        for chunk in prop.edt.0[1..].chunks(3) {
            let eoj = EOJ::try_from(chunk.to_vec())?;
            instances.push(eoj);
        }
        Ok(Self {
            eoj: p.seoj.clone(),
            instances,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SVI([ElU8; 4]);

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct SyncResponse {
    pub eoj: EOJ,
    pub svi: SVI, // Standard Version Information
    pub anno_props: Vec<ElU8>,
    pub get_props: Vec<ElU8>,
    pub set_props: Vec<ElU8>,
}

impl TryFrom<&Packet> for SyncResponse {
    type Error = anyhow::Error;

    fn try_from(p: &Packet) -> anyhow::Result<Self> {
        if !p.is_normal_response() {
            anyhow::bail!("not a response");
        }
        let controller = EOJ::try_from(vec![ElU8(0x05), ElU8(0xFF), ElU8(0x01)]).unwrap();
        if !p.is_to(&controller) {
            anyhow::bail!("invalid DEOJ");
        }
        let Some(svi) = p.get_prop(ElU8(0x82)) else {
            anyhow::bail!("not found standard version information");
        };
        let Some(anno) = p.get_prop(ElU8(0x9D)) else {
            anyhow::bail!("not found announcement property map");
        };
        let Some(get) = p.get_prop(ElU8(0x9F)) else {
            anyhow::bail!("not found get property map");
        };
        let Some(set) = p.get_prop(ElU8(0x9E)) else {
            anyhow::bail!("not found set property map");
        };
        Ok(Self {
            eoj: p.seoj.clone(),
            svi: SVI([svi.edt.0[0], svi.edt.0[1], svi.edt.0[2], svi.edt.0[3]]),
            anno_props: parse_property_map(&anno.edt),
            get_props: parse_property_map(&get.edt),
            set_props: parse_property_map(&set.edt),
        })
    }
}

fn parse_property_map(edt: &EDT) -> Vec<ElU8> {
    // the first byte always shows the number of properties
    if edt.0[0].0 < 16 {
        // if the number of properties is less than 16, each of the rest bytes represents a property
        return edt.0[1..].to_vec();
    }
    // if the number of properties is more than or equal to 16,
    // the properties are represented by the bits of the rest bytes
    //             |   7  |   6  |   5  |   4  |   3  |   2  |   1  |   0  |
    // | --------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
    // |  2nd byte | 0xF0 | 0xE0 | 0xD0 | 0xC0 | 0xB0 | 0xA0 | 0x90 | 0x80 |
    // |  3rd byte | 0xF1 | 0xE1 | 0xD1 | 0xC1 | 0xB1 | 0xA1 | 0x91 | 0x81 |
    // |       ... |  ... |  ... |  ... |  ... |  ... |  ... |  ... |  ... |
    // | 17th byte | 0xFF | 0xEF | 0xDF | 0xCF | 0xBF | 0xAF | 0x9F | 0x8F |
    let mut props = Vec::with_capacity(edt.0[0].0.into());
    for (i, b) in edt.0[1..].iter().enumerate() {
        for j in 0..(8 * size_of::<u8>()) {
            if b.0 & (1 << j) != 0 {
                props.push(ElU8((0x80 + 0x10 * j as u8) + i as u8));
            }
        }
    }
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ElU16, ElU8, Prop, EDT, ESV};

    #[test]
    fn test_parse_property_map() {
        {
            let edt = EDT(vec![
                ElU8(0x08),
                ElU8(0x80),
                ElU8(0x81),
                ElU8(0x8f),
                ElU8(0x93),
                ElU8(0xa0),
                ElU8(0xa3),
                ElU8(0xb0),
                ElU8(0xb3),
            ]);
            assert_eq!(
                parse_property_map(&edt),
                vec![
                    ElU8(0x80),
                    ElU8(0x81),
                    ElU8(0x8f),
                    ElU8(0x93),
                    ElU8(0xa0),
                    ElU8(0xa3),
                    ElU8(0xb0),
                    ElU8(0xb3),
                ]
            );
        }
        {
            let edt = EDT(vec![
                ElU8(0x12),
                ElU8(0x0d),
                ElU8(0x01),
                ElU8(0x01),
                ElU8(0x0f),
                ElU8(0x00),
                ElU8(0x00),
                ElU8(0x00),
                ElU8(0x00),
                ElU8(0x01),
                ElU8(0x01),
                ElU8(0x01),
                ElU8(0x08),
                ElU8(0x00),
                ElU8(0x02),
                ElU8(0x0a),
                ElU8(0x03),
            ]);
            assert_eq!(
                parse_property_map(&edt),
                vec![
                    ElU8(0x80),
                    ElU8(0xA0),
                    ElU8(0xB0),
                    ElU8(0x81),
                    ElU8(0x82),
                    ElU8(0x83),
                    ElU8(0x93),
                    ElU8(0xA3),
                    ElU8(0xB3),
                    ElU8(0x88),
                    ElU8(0x89),
                    ElU8(0x8A),
                    ElU8(0xBB),
                    ElU8(0x9D),
                    ElU8(0x9E),
                    ElU8(0xBE),
                    ElU8(0x8F),
                    ElU8(0x9F)
                ]
            );
        }
    }

    #[test]
    fn test_sync_response_try_from() {
        let packet = Packet {
            tid: ElU16(0x01),
            seoj: EOJ::try_from(vec![ElU8(0x01), ElU8(0x30), ElU8(0x01)]).unwrap(),
            deoj: EOJ::try_from(vec![ElU8(0x05), ElU8(0xFF), ElU8(0x01)]).unwrap(),
            esv: ESV::GetRes,
            opc: ElU8(0x03),
            props: vec![
                Prop {
                    epc: ElU8(0x82),
                    pdc: ElU8(0x04),
                    edt: EDT(vec![ElU8(0x00), ElU8(0x00), ElU8(0x52), ElU8(0x00)]),
                },
                Prop {
                    epc: ElU8(0x9D),
                    pdc: ElU8(0x07),
                    edt: EDT(vec![
                        ElU8(0x06),
                        ElU8(0x80),
                        ElU8(0x81),
                        ElU8(0x88),
                        ElU8(0x8F),
                        ElU8(0xA0),
                        ElU8(0xB0),
                    ]),
                },
                Prop {
                    epc: ElU8(0x9E),
                    pdc: ElU8(0x09),
                    edt: EDT(vec![
                        ElU8(0x08),
                        ElU8(0x80),
                        ElU8(0x81),
                        ElU8(0x8F),
                        ElU8(0x93),
                        ElU8(0xA0),
                        ElU8(0xA3),
                        ElU8(0xB0),
                        ElU8(0xB3),
                    ]),
                },
                Prop {
                    epc: ElU8(0x9F),
                    pdc: ElU8(0x11),
                    edt: EDT(vec![
                        ElU8(0x12),
                        ElU8(0x0D),
                        ElU8(0x01),
                        ElU8(0x01),
                        ElU8(0x0F),
                        ElU8(0x00),
                        ElU8(0x00),
                        ElU8(0x00),
                        ElU8(0x00),
                        ElU8(0x01),
                        ElU8(0x01),
                        ElU8(0x01),
                        ElU8(0x08),
                        ElU8(0x00),
                        ElU8(0x02),
                        ElU8(0x0A),
                        ElU8(0x03),
                    ]),
                },
            ],
        };
        let response = SyncResponse::try_from(&packet);
        if response.is_err() {
            dbg!(&response);
        }
        assert!(response.is_ok());
        assert_eq!(
            response.unwrap(),
            SyncResponse {
                eoj: EOJ::try_from(vec![ElU8(0x01), ElU8(0x30), ElU8(0x01)]).unwrap(),
                svi: SVI([ElU8(0x00), ElU8(0x00), ElU8(0x52), ElU8(0x00)]),
                anno_props: vec![
                    ElU8(0x80),
                    ElU8(0x81),
                    ElU8(0x88),
                    ElU8(0x8F),
                    ElU8(0xA0),
                    ElU8(0xB0),
                ],
                set_props: vec![
                    ElU8(0x80),
                    ElU8(0x81),
                    ElU8(0x8F),
                    ElU8(0x93),
                    ElU8(0xA0),
                    ElU8(0xA3),
                    ElU8(0xB0),
                    ElU8(0xB3),
                ],
                get_props: vec![
                    ElU8(0x80),
                    ElU8(0xA0),
                    ElU8(0xB0),
                    ElU8(0x81),
                    ElU8(0x82),
                    ElU8(0x83),
                    ElU8(0x93),
                    ElU8(0xA3),
                    ElU8(0xB3),
                    ElU8(0x88),
                    ElU8(0x89),
                    ElU8(0x8A),
                    ElU8(0xBB),
                    ElU8(0x9D),
                    ElU8(0x9E),
                    ElU8(0xBE),
                    ElU8(0x8F),
                    ElU8(0x9F),
                ],
            }
        );
    }

    #[test]
    fn test_discovery_response_try_from() {
        let packet = Packet {
            tid: ElU16(0x01),
            seoj: EOJ::try_from(vec![ElU8(0x0E), ElU8(0xF0), ElU8(0x01)]).unwrap(),
            deoj: EOJ::try_from(vec![ElU8(0x05), ElU8(0xFF), ElU8(0x01)]).unwrap(),
            esv: ESV::GetRes,
            opc: ElU8(0x01),
            props: vec![Prop {
                epc: ElU8(0xD6),
                pdc: ElU8(0x04),
                edt: EDT(vec![
                    ElU8(0x02),
                    ElU8(0x01),
                    ElU8(0x30),
                    ElU8(0x01),
                    ElU8(0x02),
                    ElU8(0x7B),
                    ElU8(0x01),
                ]),
            }],
        };
        let response = DiscoveryResponse::try_from(&packet);
        if response.is_err() {
            dbg!(&response);
        }
        assert!(response.is_ok());
        assert_eq!(
            response.unwrap(),
            DiscoveryResponse {
                eoj: EOJ::try_from(vec![ElU8(0x0E), ElU8(0xF0), ElU8(0x01)]).unwrap(),
                instances: vec![
                    EOJ::try_from(vec![ElU8(0x01), ElU8(0x30), ElU8(0x01)]).unwrap(),
                    EOJ::try_from(vec![ElU8(0x02), ElU8(0x7B), ElU8(0x01)]).unwrap(),
                ],
            }
        );
    }
}
