use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// 首先是一些协议的常量定义,如消息类型、信息元素标识等。
// 然后定义了一些协议数据结构,如PDUSessionEstablishmentAcceptMsg,它包含了接受消息中的各种信息元素。
// 接着是一些工具函数,如tlv_decode_pdu_session_establishment_accept用于从字节数据解析出消息结构。
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

// const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_IEI: u8 = 0x59;
const _PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI: u8 = 0x29;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI: u8 = 0x56;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI: u8 = 0x22;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI: u8 = 0x78;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI: u8 = 0x7B;
const _PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI: u8 = 0x25;

// const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE: u16 = 1 << 3;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u16 = 1 << 4;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_PRESENCE: u16 = 1 << 8;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE: u16 = 1 << 9;
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
pub struct PduSessionEstablishmentAcceptMsg {
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

impl PduSessionEstablishmentAcceptMsg {
    pub fn new() -> Self {
        PduSessionEstablishmentAcceptMsg {
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

const PDU_SESSION_ESTABLISHMENT_ACCEPT_5_GSM_CAUSE_IEI: u8 = 0x59;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_RQ_TIMER_IEI: u8 = 0x56;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYS_ON_IEI: u8 = 0x08;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_CP_ONLY_IEI: u8 = 0xc0;

const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI: u8 = 0x56;

const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI: u8 = 0x29;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI: u8 = 0x22;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI: u8 = 0x78;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI: u8 = 0x7B;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ATSSS_IEI: u8 = 0x77;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI: u8 = 0x25;

const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE: u16 = 1 << 3;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u16 = 1 << 4;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_PRESENCE: u16 = 1 << 8;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE: u16 = 1 << 9;

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

impl PduSessionEstablishmentAcceptMsg {
    /**
     * 3GPP TS 24501 8.3.2.1
     */
    pub fn tlv_decode_pdu_session_establishment_accept(
        data: Vec<u8>,
    ) -> Result<PduSessionEstablishmentAcceptMsg, ()> {
        let mut index: usize = 0;
        let mut res: PduSessionEstablishmentAcceptMsg = PduSessionEstablishmentAcceptMsg::new();
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
        index += 1;
        //seleted pdu session type and seleted ssc mode are in one octet!
        res.pdusessiontype.pdu_session_type_value =
            PduAddressType::from_u8(data[index] & 0b00000111);
        index += 1;
        //decode_qos_rules
        let value: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;
        res.qosrules = QOSRules::decode(data[index..].to_vec());
        let length = value as usize;
        index += 2;
        index += length;
        //decode_session_ambr
        let length1 = data[index] as usize;
        index += 1;
        index += length1;

        //begin TLV

        while index < data.len() {
            let current_tag = data[index];
            let length: usize;
            let is_match = match current_tag {
                PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_ATSSS_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI => 1,
                PDU_SESSION_ESTABLISHMENT_ACCEPT_5_GSM_CAUSE_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_RQ_TIMER_IEI => 2,
                PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI
                | PDU_SESSION_ESTABLISHMENT_ACCEPT_CP_ONLY_IEI => 3,
                _ => 0,
            };

            if is_match == 1 {
                let value: u16 = (data[index + 1] as u16) << 8 | data[index + 2] as u16;
                length = value as usize;
                // println!("TLV-E {} index {} len {}", current_tag, index, length);
            } else if is_match == 0 {
                length = data[index + 1] as usize;
                // println!("TLV {} index {}", current_tag, index);
            } else if is_match == 2 {
                length = 2;
                // println!("TV 2 {} index {}", current_tag, index);
            } else {
                length = 1;
                // println!("TV 1 {} index {}", current_tag, index);
            }

            if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI {
                let value = data[index + 2..index + 2 + length].to_vec();
                let _dnn_index = res.dnn.set_value(&value, 0, length);
                // let string = std::str::from_utf8(&value).unwrap(); // 解析切片为字符串
                res.dnn.to_string();
            }

            if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI {
                let value = data[index..index + 3 + length].to_vec();
                // let string = std::str::from_utf8(&value).unwrap(); // 解析切片为字符串
                // print!("{:#?}\n",value);
                res.extendedprotocolconfigurationoptions = parse_extended_pco(&value).unwrap();
            }

            if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI {
                let ip_len;

                let value = data[index + 2..index + 2 + length].to_vec();
                res.pduaddress.pdu_session_type_value = PduAddressType::from_u8(value[0]);
                if res.pduaddress.pdu_session_type_value == PduAddressType::IPV4 {
                    ip_len = 4;
                } else if res.pduaddress.pdu_session_type_value == PduAddressType::IPV6 {
                    ip_len = 8;
                } else if res.pduaddress.pdu_session_type_value == PduAddressType::IPV4V6 {
                    ip_len = 12;
                } else {
                    ip_len = 4;
                }
                res.pduaddress
                    .pdu_address_information
                    .set_value(&value, 1, ip_len);
            }

            if is_match == 1 {
                index += 3 + length;
            } else if is_match == 0 {
                index += 2 + length;
            } else if is_match == 2 {
                index += length;
            } else {
                index += length;
            }
        }
        return Ok(res);
    }
}
#[test]
fn pdu_sess_accept_msg() {
    let mut pduSessionEstablishmentAcceptMsg =
        PduSessionEstablishmentAcceptMsg::tlv_decode_pdu_session_establishment_accept(vec![
            0x2e, 0x01, 0x01, 0xc2, 0x12, 0x00, 0x09, 0x01, 0x00, 0x06, 0x31, 0x20, 0x01, 0x01,
            0xff, 0x01, 0x06, 0x01, 0x27, 0x10, 0x01, 0x27, 0x10, 0x59, 0x33, 0x29, 0x09, 0x02,
            0x17, 0x7c, 0x23, 0x76, 0xb8, 0x11, 0xe4, 0xbe, 0x22, 0x04, 0x01, 0x00, 0x00, 0x00,
            0x79, 0x00, 0x06, 0x01, 0x20, 0x41, 0x01, 0x01, 0x05, 0x7b, 0x00, 0x27, 0x80, 0x00,
            0x01, 0x10, 0x24, 0x0e, 0x00, 0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x24, 0x00, 0x01, 0x10, 0x24, 0x0e, 0x00, 0x66, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x25, 0x04, 0x03, 0x69, 0x6d,
            0x73,
        ]);

    println!("{:#?}", pduSessionEstablishmentAcceptMsg);
}
