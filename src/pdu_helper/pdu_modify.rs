use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// 首先是一些协议的常量定义,如消息类型、信息元素标识等。
// 然后定义了一些协议数据结构,如PDUSessionEstablishmentAcceptMsg,它包含了接受消息中的各种信息元素。
// 接着是一些工具函数,如tlv_decode_pdu_session_MODIFY用于从字节数据解析出消息结构。
// 主函数中,传入了一段字节数组,调用tlv_decode函数解析出了PDUSessionEstablishmentAcceptMsg结构,并打印出来。
// 主要的逻辑是:

// 根据协议,确定消息的组成部分,如discriminator、消息类型、信息元素等。
// 定义对应的数据结构,包含必要的字段。
// 解析函数根据协议的格式,逐步解析字节数据,填充到数据结构中。
// 这样就可以从字节流中解析出结构化的协议消息。
// 参数容器
#[derive(Debug, Clone)]
struct ParamContainer {
    _container_id: u16,
    _container_len: u8,
    _container_content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExtProtoCfgOpts {
    _length: u16,
    //   config_proto: u8,
    _pco_units: Vec<ParamContainer>,
}

impl Default for ParamContainer {
    fn default() -> Self {
        Self {
            _container_id: 0,
            _container_len: 0,
            _container_content: Vec::new(),
        }
    }
}

impl Default for ExtProtoCfgOpts {
    fn default() -> Self {
        Self {
            _length: 0,
            _pco_units: Vec::new(),
        }
    }
}

impl ParamContainer {
    pub fn to_ipv6_addr(&mut self) -> Option<Ipv6Addr> {
        if self._container_len == 16 {
            // 8 * 16 = 128 bit ipv6
            let array: [u8; 16] = self._container_content.as_slice().try_into().unwrap();
            Some(Ipv6Addr::from(array));
        }
        None
    }
}

impl ExtProtoCfgOpts {
    pub fn get_pcscf_v6_addr(&mut self) -> Option<Ipv6Addr> {
        let pco_units = self._pco_units.clone();

        for mut param_container in pco_units {
            if param_container._container_id == 0x0001 {
                let array: [u8; 16] = param_container
                    ._container_content
                    .as_slice()
                    .try_into()
                    .unwrap();
                // debug!("pcscf {:#?}", array);
                // debug!("pcscf v6 {:#?}", Ipv6Addr::from(array));
                // Ipv6Addr::from(param_container._container_content);
                return Some(Ipv6Addr::from(array));
                // return None;
            }
        }
        return None;
    }

    pub fn get_dns_v6_addr(&mut self) -> Option<Ipv6Addr> {
        let pco_units = self._pco_units.clone();

        for mut param_container in pco_units {
            if param_container._container_id == 0x0003 {
                return param_container.to_ipv6_addr();
            }
        }
        None
    }
}

// 解析函数
pub fn parse_extended_pco(data: &[u8]) -> Option<ExtProtoCfgOpts> {
    let mut params = vec![];

    let mut _i = 3; // 前4字节是类型和长度
    let length = u16::from_be_bytes([data[1], data[2]]);
    // print!("{:#?}\n",length);
    let mut i = 4;
    // 解析附加参数列表
    while i < data.len() {
        let container_id = u16::from_be_bytes([data[i], data[i + 1]]);
        // print!("{:#?}\n",container_id);

        let container_len = data[i + 2];
        let container_content = &data[i + 3..i + 3 + container_len as usize];

        let container = ParamContainer {
            _container_id: container_id,
            _container_len: container_len,
            _container_content: container_content.to_vec(),
        };

        params.push(container);

        i += 3 + container_len as usize;
    }
    let ext: ExtProtoCfgOpts = ExtProtoCfgOpts {
        _length: length,
        _pco_units: params,
    };
    Some(ext)
    // 输出解析结果
}

// const PDU_SESSION_MODIFY__5GSM_CAUSE_IEI: u8 = 0x59;
const _PDU_SESSION_MODIFY_PDU_ADDRESS_IEI: u8 = 0x29;
// const PDU_SESSION_MODIFY_GPRS_TIMER_IEI: u8 = 0x56;
// const PDU_SESSION_MODIFY_SNSSAI_IEI: u8 = 0x22;
// const PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
// const PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
// const PDU_SESSION_MODIFY_EAP_MESSAGE_IEI: u8 = 0x78;
// const PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
// const PDU_SESSION_MODIFY_EPCO_IEI: u8 = 0x7B;
const _PDU_SESSION_MODIFY_DNN_IEI: u8 = 0x25;

// const PDU_SESSION_MODIFY__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
// const PDU_SESSION_MODIFY_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
// const PDU_SESSION_MODIFY_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
// const PDU_SESSION_MODIFY_SNSSAI_PRESENCE: u16 = 1 << 3;
// const PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u16 = 1 << 4;
// const PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
// const PDU_SESSION_MODIFY_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
// const PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
// const PDU_SESSION_MODIFY_EPCO_PRESENCE: u16 = 1 << 8;
// const PDU_SESSION_MODIFY_DNN_PRESENCE: u16 = 1 << 9;
// use std::mem::ManuallyDrop;

use std::alloc::alloc;
use std::alloc::Layout;
use std::slice;

use crate::pdu_helper::qos_rules::{
    DestinationMACAddressRange, Ethertype, FlowLabel, IPv4FilterAddress, IPv6FilterAddress,
    MACAddress, PacketFilterComponentType, PacketFilterComponentValue, PacketFilterContent,
    PacketFilterListDeletePFList, PacketFilterListEnum, PacketFilterListUpdatePFList, Port,
    PortRange, ProtocolIdentifierNextHeader, QOSRulesIE, RuleOperationCode, SecurityParameterIndex,
    SourceMACAddressRange, TypeOfServiceTrafficClass, VlanCtagPcpdei, VlanCtagVid, VlanStagPcpdei,
    VlanStagVid,
};

use super::pdu_helper::{
    ExtendedProtocolDiscriminator, PDUSessionIdentity, PduSessionPlainMsg,
    ProcedureTransactionIdentity, SessionMessageType,
};
use super::qos_rules::QOSRules;

#[derive(Debug, PartialEq, Clone)]
pub enum PduAddressType {
    IPV4,
    IPV6,
    IPV4V6,
    Unknown,
}

impl PduAddressType {
    pub fn from_u8(val: u8) -> PduAddressType {
        match val {
            0b00000001 => PduAddressType::IPV4,
            0b00000010 => PduAddressType::IPV6,
            0b00000011 => PduAddressType::IPV4V6,
            _ => PduAddressType::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct PduSessioModifyMsg {
    pub extendedprotocoldiscriminator: ExtendedProtocolDiscriminator,
    pub pdusessionidentity: PDUSessionIdentity,
    pub proceduretransactionidentity: ProcedureTransactionIdentity,
    pub messagetype: SessionMessageType,
    pub pdusessiontype: PDUSessionType,
    pub sscmode: SSCMode,
    pub qosrules: QOSRules,
    // sessionambr: SessionAMBR,
    // presence: u16,
    // _5gsmcause: _5GSMCause,
    pub pduaddress: PDUAddress,
    // gprstimer: GPRSTimer,
    // snssai: SNSSAI,
    // alwaysonpdusessionindication: AlwaysonPDUSessionIndication,
    // mappedepsbearercontexts: MappedEPSBearerContexts,
    // eapmessage: EAPMessage,
    pub qosflowdescriptions: QOSFlowDescriptions,
    pub extendedprotocolconfigurationoptions: ExtProtoCfgOpts,
    pub dnn: DNN,
}

// pub type MessageType = u8;

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]

pub struct PDUSessionType {
    pub pdu_session_type_value: PduAddressType,
    pub spare: u8,
}

impl PDUSessionType {
    fn default() -> Self {
        PDUSessionType {
            pdu_session_type_value: PduAddressType::IPV4,
            spare: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]

pub struct SSCMode {
    pub sscModeValue: u8,
    pub spare: u8,
}

#[repr(C)]
// pub struct PacketFilterContents {
//     pub component_type: u8,
//     pub component_value: OctetString,
// }

// // impl PacketFilterContents {
// //     fn default() -> Self {
// //         PacketFilterContents {
// //             component_type: 0,
// //             component_value: 0,
// //         }
// //     }
// // }

// #[repr(C)]
// pub struct Create_ModifyAndAdd_ModifyAndReplace {
//     pub packetfilteridentifier: u8,
//     pub packetfilterdirection: u8,
//     pub spare: u8,
//     pub lenghtofpacketfiltercontents: u8,
//     pub packetfiltercontents: PacketFilterContents,
// }

// impl Create_ModifyAndAdd_ModifyAndReplace {
//     fn default() -> Self {
//         Create_ModifyAndAdd_ModifyAndReplace {
//             packetfilteridentifier: 0,
//             packetfilterdirection: 0,
//             spare: 0,
//             lenghtofpacketfiltercontents: 0,
//             packetfiltercontents: 0,
//         }
//     }
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct SessionAMBR {
//     pub uint_for_session_ambr_for_downlink: u8,
//     pub session_ambr_for_downlink: u16,
//     pub uint_for_session_ambr_for_uplink: u8,
//     pub session_ambr_for_uplink: u16,
// }

// pub type _5GSMCause = u8;
#[repr(C)]
#[derive(Debug, Clone)]

pub struct PDUAddress {
    pub pdu_session_type_value: PduAddressType,
    // pub spare: u8,
    pub pdu_address_information: OctetString,
}
impl PDUAddress {
    pub fn default() -> Self {
        PDUAddress {
            pdu_session_type_value: PduAddressType::IPV4,
            // spare: 0,
            pdu_address_information: OctetString::default(),
        }
    }
}

fn decode_dnn(input: &Vec<u8>) -> String {
    let mut index = 0usize;
    let len = input.len();
    let mut dnn_components: Vec<String> = vec![];
    while index < len {
        let length = input[index] as usize;
        index += 1;
        let dnn = String::from_utf8(input[index..index + length].to_vec());
        match dnn {
            Ok(dnn) => {
                dnn_components.push(dnn.clone());
            }
            Err(_) => {}
        }
        index += length;
    }
    let dnn = dnn_components.get(0);
    match dnn {
        Some(dnn) => dnn.to_string(),
        None => "None".to_string(),
    }
    // input = &mut input[len+1..];
}

#[repr(C)]
#[derive(Debug, Clone)]

pub struct OctetString {
    pub length: u32,
    pub value: Vec<u8>,
}
impl OctetString {
    fn default() -> Self {
        OctetString {
            length: 0,
            value: vec![],
        }
    }
    pub fn set_value(&mut self, data: &[u8], start_index: usize, length: usize) {
        self.length = length as u32;
        // self.value = std::ptr::null_mut(); // 重置value指针
        // self.value.extend_from_slice(other)

        if length > 0 {
            self.value
                .extend_from_slice(&data[start_index..start_index + length]);
            // let layout = Layout::array::<u8>(length).unwrap();
            // self.value = unsafe { alloc(layout) as *mut u8 };
            // unsafe {
            //     std::ptr::copy_nonoverlapping(data.as_ptr().add(start_index), self.value, length);
            // }
        }
    }

    pub fn to_string(&self) -> String {
        let string = String::from_utf8(self.value.clone());
        match string {
            Ok(str) => str,
            Err(_) => {
                return "None".to_owned();
            }
        }
        // string.
        // unsafe {
        //     let slice = slice::from_raw_parts(self.value, self.length.try_into().unwrap());
        //     string = std::str::from_utf8(slice).unwrap();
        // };
    }

    pub fn dnn_to_string(&mut self) -> String {
        let string = decode_dnn(&self.value);
        return string;
    }

    pub fn to_bytes_u8(&mut self) -> &[u8] {
        return &self.value;
    }
}

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct GPRSTimer {
//     pub timeValue: u8,
//     pub unit: u8,
// }

// #[repr(u8)]
// #[derive(Debug,Clone)]
// pub enum length_of_snssai_contents {
//     SST_LENGTH = 0b00000001,
//     SST_AND_MAPPEDHPLMNSST_LENGTH = 0b00000010,
//     SST_AND_SD_LENGTH = 0b00000100,
//     SST_AND_SD_AND_MAPPEDHPLMNSST_LENGTH = 0b00000101,
//     SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGTH = 0b00001000,
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct SNSSAI {
//     pub len: length_of_snssai_contents,
//     pub sst: u8,
//     pub sd: [u8; 3],
//     pub mappedhplmnsst: u8,
//     pub mappedhplmnsd: [u8; 3],
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct AlwaysonPDUSessionIndication {
//     pub apsi_indication: u8,
//     pub spare: u8,
// }

// pub type MappedEPSBearerContexts = OctetString;
// pub type EAPMessage = OctetString;

// #[repr(C)]
// #[derive(Debug,Clone)]
// pub struct ParametersList {
//     pub parameteridentifier: u8,
//     pub lengthofparametercontents: u8,
//     pub parametercontents: ParametersListContents,
// }

// #[repr(C)]
// #[derive(Debug,Clone)]
// pub struct ParametersListContents {
//     pub _5qi: u8,
//     pub gfbrormfbr_uplinkordownlink: GFBROrMFBR_UpLinkOrDownLink,
//     pub averagingwindow: AveragingWindow,
//     pub epsbeareridentity: EpsBearerIdentity,
// }
// #[repr(C)]
// #[derive(Debug,Clone)]
// pub struct EpsBearerIdentity {
//     pub spare: u8,
//     pub identity: u8,
// }

// #[repr(C)]
#[derive(Debug, Clone)]
pub struct QOSFlowDescriptionsContents {
    pub qfi: u8,
    pub operationcode: u8,
    pub numberofparameters: u8,
    pub e: u8,
    pub parameterslist: Vec<Parameter>,
}
#[derive(Debug, Clone)]
pub struct Parameter {
    pub parameter_id: u8,
    pub length_param_content: u8,
    // pub contents: Vec<ParametersList>,
}

// #[repr(C)]
#[derive(Debug, Clone)]
pub struct QOSFlowDescriptions {
    pub qosflowdescriptionsnumber: u16,
    pub qosflowdescriptionscontents: Vec<QOSFlowDescriptionsContents>,
}
impl QOSFlowDescriptions {
    pub fn default() -> QOSFlowDescriptions {
        QOSFlowDescriptions {
            qosflowdescriptionsnumber: 0,
            qosflowdescriptionscontents: vec![],
        }
    }
}

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct GFBROrMFBR_UpLinkOrDownLink {
//     pub uint: u8,
//     pub value: u16,
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct AveragingWindow {
//     pub uplinkinmilliseconds: u8,
//     pub downlinkinmilliseconds: u8,
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct ExtendedProtocolConfigurationOptions {
//     pub configurationProtocol: u8,
//     pub spare: u8,
//     pub ext: u8,
//     pub numerofProtocolId: u8,
//     pub protocolId: *mut ProtocolIdContents,
// }

// #[repr(C)]
// #[derive(Debug,Clone)]

// pub struct ProtocolIdContents {
//     pub id: u16,
//     pub lengthofContents: u8,
//     pub contents: OctetString,
// }

pub type DNN = OctetString;

impl PduSessioModifyMsg {
    pub fn new() -> Self {
        PduSessioModifyMsg {
            extendedprotocoldiscriminator: ExtendedProtocolDiscriminator::default(),
            pdusessionidentity: PDUSessionIdentity::default(),
            proceduretransactionidentity: ProcedureTransactionIdentity::default(),
            messagetype: SessionMessageType::default(),
            pdusessiontype: PDUSessionType::default(),
            // sscmode: SSCMode::default(),
            // qosrules: QOSRules::default(),
            // sessionambr: SessionAMBR::default(),
            // presence: 0,
            // _5gsmcause: _5GSMCause::default(),
            pduaddress: PDUAddress::default(),
            // gprstimer: GPRSTimer::default(),
            // snssai: SNSSAI::default(),
            // alwaysonpdusessionindication: AlwaysonPDUSessionIndication::default(),
            // mappedepsbearercontexts: MappedEPSBearerContexts::default(),
            // eapmessage: EAPMessage::default(),
            qosflowdescriptions: QOSFlowDescriptions {
                qosflowdescriptionsnumber: 0,
                qosflowdescriptionscontents: vec![],
            },
            extendedprotocolconfigurationoptions: ExtProtoCfgOpts::default(),
            dnn: DNN::default(),
            sscmode: SSCMode {
                sscModeValue: 0u8,
                spare: 0u8,
            },
            qosrules: QOSRules {
                lengthofqosrulesie: 0,
                qosrulesie: HashMap::<u8, QOSRulesIE>::new(),
            },
        }
    }

    pub fn get_dnn_name(&mut self) -> String {
        if self.dnn.length > 0 {
            return self.dnn.dnn_to_string();
        } else {
            return "".to_string();
        }
    }

    pub fn get_ipv4(&mut self) -> Result<IpAddr, &str> {
        let arr = self.pduaddress.pdu_address_information.to_bytes_u8();
        let mut _ipv6_str: String;
        let mut _ipv4_str: String;
        if arr.len() == 4 {
            let ipv4_bytes: [u8; 4] = [arr[0], arr[1], arr[2], arr[3]];
            let ipv4_addr = Ipv4Addr::from(ipv4_bytes);

            Ok(IpAddr::V4(ipv4_addr))
        } else if arr.len() == 8 {
            Err("")
        } else if arr.len() == 12 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv4_bytes: [u8; 4] = [arr[8], arr[9], arr[10], arr[11]];
            let _ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            let ipv4_addr = Ipv4Addr::from(ipv4_bytes);
            Ok(IpAddr::V4(ipv4_addr))
        } else {
            Err("")
        }
    }

    pub fn _get_ipv6(&mut self) -> Result<IpAddr, &str> {
        let arr = self.pduaddress.pdu_address_information.to_bytes_u8();
        let mut _ipv6_str: String;
        let mut _ipv4_str: String;
        if arr.len() == 4 {
            Err("")
        } else if arr.len() == 8 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Ok(IpAddr::V6(ipv6_addr))
        } else if arr.len() == 12 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv4_bytes: [u8; 4] = [arr[8], arr[9], arr[10], arr[11]];
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            let _ipv4_addr = Ipv4Addr::from(ipv4_bytes);
            Ok(IpAddr::V6(ipv6_addr))
        } else {
            Err("")
        }
    }

    pub fn get_pcscf_v6_address(&mut self) -> Ipv6Addr {
        let v6_addr = self
            .extendedprotocolconfigurationoptions
            .get_pcscf_v6_addr()
            .unwrap_or(Ipv6Addr::LOCALHOST);
        v6_addr
    }
    pub fn get_dns_v6_address(&mut self) -> Option<Ipv6Addr> {
        return self
            .extendedprotocolconfigurationoptions
            .get_pcscf_v6_addr();
    }
}

const PDU_SESSION_MODIFY_5_GSM_CAUSE_IEI: u8 = 0x59;
const PDU_SESSION_MODIFY_ALWAYS_ON_IEI: u8 = 0x08;
const PDU_SESSION_MODIFY_CP_ONLY_IEI: u8 = 0xc0;

const PDU_SESSION_MODIFY_GPRS_TIMER_IEI: u8 = 0x56;

const PDU_SESSION_MODIFY_PDU_ADDRESS_IEI: u8 = 0x29;
const PDU_SESSION_MODIFY_SNSSAI_IEI: u8 = 0x22;
const PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
/**
 * TLV-E
 */
const PDU_SESSION_MODIFY_AUTH_QOS: u8 = 0x7a;
const PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
const PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
const PDU_SESSION_MODIFY_EPCO_IEI: u8 = 0x7B;
const PDU_SESSION_MODIFY_ATSSS_IEI: u8 = 0x77;
const PDU_SESSION_MODIFY_PORT_MGMT_IEI: u8 = 0x74;
#[derive(Debug,Clone)]
pub enum TLV_E {
    PDU_SESSION_MODIFY_AUTH_QOS = 0x7a,
    PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_IEI = 0x75,
    PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_IEI = 0x79,
    PDU_SESSION_MODIFY_EPCO_IEI = 0x7B,
    PDU_SESSION_MODIFY_ATSSS_IEI = 0x77,
    PDU_SESSION_MODIFY_PORT_MGMT_IEI = 0x74,
}
impl TLV_E {
    pub fn from_u8(iei: u8) -> Option<TLV_E> {
        match iei {
            0x7a => Some(TLV_E::PDU_SESSION_MODIFY_AUTH_QOS),
            0x75 => Some(TLV_E::PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_IEI),
            0x79 => Some(TLV_E::PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_IEI),
            0x7B => Some(TLV_E::PDU_SESSION_MODIFY_EPCO_IEI),
            0x77 => Some(TLV_E::PDU_SESSION_MODIFY_ATSSS_IEI),
            0x74 => Some(TLV_E::PDU_SESSION_MODIFY_PORT_MGMT_IEI),
            _ => None,
        }
    }
}
/**
 * TLV
 */
const PDU_SESSION_MODIFY_IP_HDR_CMP: u8 = 0x66;
const PDU_SESSION_MODIFY_SESS_AMBR: u8 = 0x2a;
const PDU_SESSION_MODIFY_SER_PLMN: u8 = 0x1e;
const PDU_SESSION_MODIFY_ETH_HDR: u8 = 0x1f;
#[derive(Debug,Clone)]
pub enum TLV {
    PDU_SESSION_MODIFY_IP_HDR_CMP = 0x66,
    PDU_SESSION_MODIFY_SER_PLMN = 0x1e,
    PDU_SESSION_MODIFY_ETH_HDR = 0x1f,
    PDU_SESSION_MODIFY_SESS_AMBR = 0x2a,
    ANY,
}
impl TLV {
    pub fn from_u8(iei: u8) -> Option<TLV> {
        match iei {
            0x66 => Some(TLV::PDU_SESSION_MODIFY_IP_HDR_CMP),
            0x1e => Some(TLV::PDU_SESSION_MODIFY_SER_PLMN),
            0x1f => Some(TLV::PDU_SESSION_MODIFY_ETH_HDR),
            0x2a => Some(TLV::PDU_SESSION_MODIFY_SESS_AMBR),
            _ => None,
        }
    }
}
/**
 * TV-2
 */
const PDU_SESSION_MODIFY_RQ_TIMER_IEI: u8 = 0x56;
#[derive(Debug,Clone)]
pub enum TV_2 {
    PDU_SESSION_MODIFY_RQ_TIMER_IEI = 0x56,
    PDU_SESSION_MODIFY_5_GSM_CAUSE_IEI = 0x59,
}
impl TV_2 {
    pub fn from_u8(iei: u8) -> Option<TV_2> {
        match iei {
            0x56 => Some(TV_2::PDU_SESSION_MODIFY_RQ_TIMER_IEI),
            0x59 => Some(TV_2::PDU_SESSION_MODIFY_5_GSM_CAUSE_IEI),
            _ => None,
        }
    }
}
/**
 * TV-1
 */
const PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u8 = 0x08;
#[derive(Debug,Clone)]
pub enum TV_1 {
    PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE = 0x08,
}
impl TV_1 {
    pub fn from_u8(iei: u8) -> Option<TV_1> {
        match iei {
            0x08 => Some(TV_1::PDU_SESSION_MODIFY_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE),
            _ => None,
        }
    }
}
#[derive(Debug,Clone)]
pub enum PDU_MODIFY_IEI {
    TV_1(TV_1),
    TV_2(TV_2),
    TLV(TLV),
    TLV_E(TLV_E),
}

impl PDU_MODIFY_IEI {
    pub fn from_u8(iei: u8) -> PDU_MODIFY_IEI {
        // let tv_1 = TV_1::from_u8(iei);
        // let tv_2 = TV_2::from_u8(iei);
        // let tlv = TLV::from_u8(iei);
        // let tlv_e = TLV_E::from_u8(iei);
        if let Some(tv1) = TV_1::from_u8(iei) {
            PDU_MODIFY_IEI::TV_1(tv1)
        } else if let Some(tv2) = TV_2::from_u8(iei) {
            PDU_MODIFY_IEI::TV_2(tv2)
        } else if let Some(tlv) = TLV::from_u8(iei) {
            PDU_MODIFY_IEI::TLV(tlv)
        } else if let Some(tlv_e) = TLV_E::from_u8(iei) {
            PDU_MODIFY_IEI::TLV_E(tlv_e)
        } else {
            PDU_MODIFY_IEI::TLV(TLV::ANY)
        }
    }
}

const PDU_SESSION_MODIFY__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
const PDU_SESSION_MODIFY_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
const PDU_SESSION_MODIFY_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
const PDU_SESSION_MODIFY_SNSSAI_PRESENCE: u16 = 1 << 3;
const PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
const PDU_SESSION_MODIFY_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
const PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
const PDU_SESSION_MODIFY_EPCO_PRESENCE: u16 = 1 << 8;
const PDU_SESSION_MODIFY_DNN_PRESENCE: u16 = 1 << 9;

pub const _NR_NETWORK_IF_MGMT_CREATE: u8 = 0x00;
pub const _NR_NETWORK_IF_MGMT_UPDATE: u8 = 0x01;
pub const _NR_NETWORK_IF_MGMT_DELETE: u8 = 0x11;
pub const _NR_NETWORK_IF_MGMT_DESTORY: u8 = 0xff;

pub fn tlv_decode_nr_network_if_mgm(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut index = 0;
    while index < data.len() {
        let current_tag = data[index];
        let length = data[index + 1] as usize;

        if current_tag == _NR_NETWORK_IF_MGMT_CREATE {
            let value = data[index + 2..index + 2 + length].to_vec();
            return Some((current_tag, value));
        }

        if current_tag == _NR_NETWORK_IF_MGMT_UPDATE {
            let value = data[index + 2..index + 2 + length].to_vec();
            return Some((current_tag, value));
        }

        if current_tag == _NR_NETWORK_IF_MGMT_DESTORY {
            let value = Vec::new();
            return Some((current_tag, value));
        }

        index += 2 + length;
    }

    None
}

impl PduSessioModifyMsg {
    /**
     * 3GPP TS 24501 8.3.9.1
     */
    pub fn tlv_decode_pdu_session_modify_msg(data: Vec<u8>) -> Result<PduSessioModifyMsg, ()> {
        let mut index: usize = 0;
        let mut res: PduSessioModifyMsg = PduSessioModifyMsg::new();
        // println!("{:?}", data);
        //decode extended_protocol_discriminator
        res.extendedprotocoldiscriminator = data[index];
        index += 1;
        //decode_pdu_session_identity/scc
        res.pdusessionidentity = data[index];
        index += 1;
        //decode_procedure_transaction_identity
        res.proceduretransactionidentity = data[index];
        index += 1;
        //decode_message_type
        res.messagetype = SessionMessageType::ModificationCommand;
        index += 1;

        //begin TLV

        while index < data.len() {
            let current_tag = data[index];
            let length: usize;
            let pdu_modify_iei = PDU_MODIFY_IEI::from_u8(current_tag);
            match pdu_modify_iei {
                PDU_MODIFY_IEI::TV_1(_) => {
                    length = 1;
                    index += length;
                }
                PDU_MODIFY_IEI::TV_2(_) => {
                    length = 2;
                    index += length;
                }
                PDU_MODIFY_IEI::TLV(_) => {
                    length = data[index + 1] as usize;
                    index += 2 + length;
                }
                PDU_MODIFY_IEI::TLV_E(tlv_e) => {
                    let value: u16 = (data[index + 1] as u16) << 8 | data[index + 2] as u16;
                    length = value as usize;

                    match tlv_e {
                        TLV_E::PDU_SESSION_MODIFY_AUTH_QOS => {
                            let value = data[index+1..index + 3 + length].to_vec();
                            res.qosrules = QOSRules::decode(value);
                        }
                        TLV_E::PDU_SESSION_MODIFY_MAPPED_EPS_BEARER_CONTEXTS_IEI => {}
                        TLV_E::PDU_SESSION_MODIFY_QOS_FLOW_DESCRIPTIONS_IEI => {}
                        TLV_E::PDU_SESSION_MODIFY_EPCO_IEI => {}
                        TLV_E::PDU_SESSION_MODIFY_ATSSS_IEI => {}
                        TLV_E::PDU_SESSION_MODIFY_PORT_MGMT_IEI => {}
                    }
                    index += 3 + length;
                }
            };
        }
        return Ok(res);
    }
}
#[test]
fn main_test_vonr_mt_modify() {
    let mut pduSessionModifytMsg = PduSessioModifyMsg::tlv_decode_pdu_session_modify_msg(vec![
        0x2e, 0x01, 0x00, 0xcb, 0x7a, 0x00, 0x7c, 0x02, 0x00, 0x3b, 0x22, 0x20, 0x1a, 0x21, 0x24,
        0x0e, 0x00, 0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x25,
        0x80, 0x30, 0x11, 0x40, 0x0f, 0xa1, 0x50, 0x91, 0xf9, 0x11, 0x1a, 0x21, 0x24, 0x0e, 0x00,
        0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x25, 0x80, 0x30,
        0x11, 0x40, 0x0f, 0xa1, 0x50, 0x91, 0xf9, 0xbe, 0x02, 0x03, 0x00, 0x3b, 0x22, 0x22, 0x1a,
        0x21, 0x24, 0x0e, 0x00, 0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x25, 0x80, 0x30, 0x11, 0x40, 0x0f, 0xa0, 0x50, 0x91, 0xf8, 0x13, 0x1a, 0x21, 0x24,
        0x0e, 0x00, 0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x25,
        0x80, 0x30, 0x11, 0x40, 0x0f, 0xa0, 0x50, 0x91, 0xf8, 0xbd, 0x02, 0x79, 0x00, 0x1a, 0x02,
        0x20, 0x45, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0x00, 0x2c, 0x03, 0x03, 0x01, 0x00, 0x2c,
        0x04, 0x03, 0x01, 0x00, 0x2c, 0x05, 0x03, 0x01, 0x00, 0x2c,
    ]);

    println!("{:#?}", pduSessionModifytMsg);
}

#[test]
fn main_test_vonr_mt_release_modify() {
    let mut pduSessionModifytMsg = PduSessioModifyMsg::tlv_decode_pdu_session_modify_msg(vec![
        0x2e,0x01,0x00,0xcb,0x7a,0x00,0x08,0x02,0x00,0x01,0x40,0x03,0x00,0x01,0x40,0x79,0x00,0x03,
        0x02,0x40,0x00
    ]);

    println!("{:#?}", pduSessionModifytMsg);
}