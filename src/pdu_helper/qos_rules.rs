use std::collections::HashMap;

use log::debug;
use pnet::packet::{ipv6::Ipv6Packet, ipv4::Ipv4Packet};

#[repr(C)]
#[derive(Debug,Clone)]

pub struct QOSRules {
    pub lengthofqosrulesie: u16,
    pub qosrulesie: HashMap<u8, QOSRulesIE>,
}

impl QOSRules {
    pub fn reflect_pkt_to_qfi(&self, pkt_buffer:Vec<u8>) -> u8 {
        //Decode pkt_buffer into IP Packet
       
        let headerV6 =  Ipv6Packet::new(&pkt_buffer);
         //get all up link pkt filters
         let mut default_qfi = 1u8;
         let mut choice_qfi = 0u8;
         let qfi_pkt_map : HashMap<u8,Vec<PacketFilterListUpdatePFList>> = HashMap::<u8,Vec<PacketFilterListUpdatePFList>>::new();
        match headerV6 {
        Some(hdr_v6) => {
              //仅判断ipv6，现阶段
              match hdr_v6.get_version() {
                6 => {
                    'outer : for qos_rule in &self.qosrulesie {
                        if qos_rule.1.dqrbit == 1 {
                            default_qfi = qos_rule.1.qosflowidentifer;
                        }
                        'mid : for pkt_filter in &qos_rule.1.packetfilterlist {
                            
                            match  pkt_filter {
                                PacketFilterListEnum::PacketFilterListDeletePFList(_) => {},
                                PacketFilterListEnum::PacketFilterListUpdatePFList(filters) => {
                                    match  filters.packet_filter_direction {
                                        pkt_direction::DOWNLINK_ONLY => {},
                                        pkt_direction::UPLINK_ONLY => {
                                            'inner : for  filter in &filters.packet_filter_content_list {
            
                                                match &filter.packet_filter_content_value {
                                                    PacketFilterComponentValue::MatchAll => {},
                                                    PacketFilterComponentValue::IPv4RemoteAddress(_) => {},
                                                    PacketFilterComponentValue::IPv4LocalAddress(_) => {},
                                                    PacketFilterComponentValue::IPv6RemoteAddressPrefixLength(f) => {
            
                                                        //仅判断ipv6，现阶段
                                                                // debug!("{:#?}",f);
                                                                if hdr_v6.get_destination().octets().to_vec() == f.ipv6_address {
                                                                    choice_qfi = qos_rule.1.qosflowidentifer;
                                                                    break 'outer ;
                                                                }
                     
                                                    },
                                                    PacketFilterComponentValue::IPv6LocalAddressPrefixLength(_) => {},
                                                    PacketFilterComponentValue::ProtocolIdentifierNextHeader(_) => {},
                                                    PacketFilterComponentValue::SingleLocalPort(_) => {},
                                                    PacketFilterComponentValue::LocalPortRange(_) => {},
                                                    PacketFilterComponentValue::SingleRemotePort(_) => {},
                                                    PacketFilterComponentValue::RemotePortRange(_) => {},
                                                    PacketFilterComponentValue::SecurityParameterIndex(_) => {},
                                                    PacketFilterComponentValue::TypeOfServiceTrafficClass(_) => {},
                                                    PacketFilterComponentValue::FlowLabel(_) => {},
                                                    PacketFilterComponentValue::DestinationMACAddress(_) => {},
                                                    PacketFilterComponentValue::SourceMACAddress(_) => {},
                                                    PacketFilterComponentValue::VlanCtagVid(_) => {},
                                                    PacketFilterComponentValue::VlanStagVid(_) => {},
                                                    PacketFilterComponentValue::VlanCtagPcpdei(_) => {},
                                                    PacketFilterComponentValue::VlanStagPcpdei(_) => {},
                                                    PacketFilterComponentValue::Ethertype(_) => {},
                                                    PacketFilterComponentValue::DestinationMACAddressRange(_) => {},
                                                    PacketFilterComponentValue::SourceMACAddressRange(_) => {},
                                                }
                                            }
                                        },
                                        pkt_direction::DUAL_DIRECTION => {},
                                        pkt_direction::RESERVED => {},
                                    }
                                },
                                PacketFilterListEnum::PacketFilterListOpOnePF(_) => {},
                                PacketFilterListEnum::PacketFilterNone => {},
                            }
                        }
                    }
             
                        },
                4 => {
                    let hdr_v4 = Ipv4Packet::new(&pkt_buffer).unwrap();
                    // println!("IpAddr {:#?}", hdr_v4.get_destination());

                },
                _ => {

                }

                    }
                },
                _ => {
                    // return default_qfi; 
                }
            }      

       
        if choice_qfi > 0 {

            // println!("[TEST] reflect to qfi {:?}" ,choice_qfi );
            return choice_qfi;

        }
        else {
            // println!("[TEST]  no matches reflect to default qfi {:?}" ,default_qfi );
            return default_qfi;
        }
    }
}

#[repr(C)]
#[derive(Debug,Clone)]

pub struct QOSRulesIE {
    pub qosruleidentifer: u8,
    pub lengthof_qo_srule: u16,
    pub numberofpacketfilters: u8,
    pub dqrbit: u8,
    /**
    * Rule operation code (bits 8 to 6 of octet 7)
    *       Bits
    *       8 7 6
    *       0 0 0	Reserved
    *       0 0 1	Create new QoS rule
    *       0 1 0	Delete existing QoS rule
    *       0 1 1	Modify existing QoS rule and add packet filters
    *       1 0 0	Modify existing QoS rule and replace all packet filters
    *       1 0 1	Modify existing QoS rule and delete packet filters
    *       1 1 0	Modify existing QoS rule without modifying packet filters
    *       1 1 1	Reserved
    */
    pub ruleoperationcode: RuleOperationCode,
    pub packetfilterlist: Vec<PacketFilterListEnum>,
    pub qosruleprecedence: u8,
    pub qosflowidentifer: u8,
    pub segregation: u8,
    pub spare: u8,
}
#[derive(Debug,Clone)]
pub enum RuleOperationCode {
    Reserved,
    CreateNewQosRule = 0b00000001,
    DeleteExistingQosRule = 0b00000010,
    ModifyExistingQosRuleAndAddPackerFilters = 0b00000011,
    ModifyExistingQosRuleAndReplacePackerFilters = 0b00000100,
    ModifyExistingQosRuleAndDeletePackerFilters = 0b00000101,
    ModifyExistingQosRuleWithoutModifyPackerFilters = 0b00000110,
    
}
impl RuleOperationCode {
    pub fn from_u8(data: u8) -> RuleOperationCode {
        match data {
            0b00000001 =>{
                RuleOperationCode::CreateNewQosRule
            },
            0b00000010 =>{
                RuleOperationCode::DeleteExistingQosRule
            },
            0b00000011 =>{
                RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters
            },
            0b00000100 =>{
                RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters
            },
            0b00000101 =>{
                RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters
            },
            0b00000110 =>{
                RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters
            },
            _ => {
                RuleOperationCode::Reserved
            }
        }
    }
}
#[derive(Debug,Clone)]
pub enum PacketFilterListEnum {
    PacketFilterListDeletePFList(PacketFilterListDeletePFList),
    PacketFilterListUpdatePFList(PacketFilterListUpdatePFList),
    PacketFilterListOpOnePF(PacketFilterSingle),
    PacketFilterNone,
}

#[derive(Debug,Clone)]

pub struct PacketFilterSingle {
    pub packet_fliter_id: u8,
}

#[repr(C)]
#[derive(Debug,Clone)]

pub struct PacketFilterListDeletePFList {
    pub packet_fliter_id: Vec<u8>,
}
#[repr(C)]
#[derive(Debug,Clone)]

pub struct PacketFilterListUpdatePFList {
    pub packet_filter_direction: pkt_direction,
    pub packet_filter_id: u8,
    pub length_packet_filter_contents: u8,
    pub packet_filter_content_list: Vec<PacketFilterContent>,
}

#[derive(Debug,Clone)]
pub enum pkt_direction {
    DOWNLINK_ONLY = 0b00000001,
    UPLINK_ONLY = 0b00000010,
    DUAL_DIRECTION = 0b00000011,
    RESERVED = 0b00000000,
}
impl pkt_direction {
    /**
    ```
    The packet filter direction field is used to indicate for what traffic direction the filter applies.
    Bits
    6 5
    0 0	reserved
    0 1	downlink only
    1 0	uplink only
    1 1	bidirectional (see NOTE)
    ```
*/
    pub fn from_u8(ie :u8) -> pkt_direction {
        match ie {
            0b00000001 => {
                pkt_direction::DOWNLINK_ONLY
            },
            0b00000010 => {
                pkt_direction::UPLINK_ONLY
            },
            0b00000011 => {
                pkt_direction::DUAL_DIRECTION
            },
            _ => {
                pkt_direction::RESERVED
            }
        }
    }
}

#[derive(Debug,Clone)]
pub struct PacketFilterContent {
    pub packet_filter_content_type: PacketFilterComponentType,
    pub packet_filter_content_value: PacketFilterComponentValue,
}
#[derive(Debug,Clone)]
pub enum PacketFilterComponentType {
    MatchAll = 0b00000001,
    IPv4RemoteAddress = 0b00010000,
    IPv4LocalAddress = 0b00010001,
    IPv6RemoteAddressPrefixLength = 0b00100001,
    IPv6LocalAddressPrefixLength = 0b00100011,

    ProtocolIdentifierNextHeader = 0b00110000, //ok
    SingleLocalPort = 0b01000000,//
    LocalPortRange = 0b01000001,
    SingleRemotePort = 0b01010000,
    RemotePortRange = 0b01010001,

    SecurityParameterIndex = 0b01100000,
    TypeOfServiceTrafficClass = 0b01110000,
    FlowLabel = 0b10000000,

    DestinationMACAddress = 0b10000001,
    SourceMACAddress = 0b10000010,
    VlanCtagVid = 0b10000011,
    VlanStagVid = 0b10000100,
    VlanCtagPcpdei = 0b10000101,
    VlanStagPcpdei = 0b10000110,
    Ethertype = 0b10000111,

}
impl PacketFilterComponentType {
    pub fn from_u8(data: u8) -> PacketFilterComponentType {
        match data {
            // MatchAll = 0b00000001,
            0b00000001 => PacketFilterComponentType::MatchAll,
            // IPv4RemoteAddress = 0b00010000,
            0b00010000 => PacketFilterComponentType::IPv4RemoteAddress,

            // IPv4LocalAddress = 0b00010001,
            0b00010001 => PacketFilterComponentType::IPv4LocalAddress,
            // IPv6RemoteAddressPrefixLength = 0b00100001,
            0b00100001 => PacketFilterComponentType::IPv6RemoteAddressPrefixLength,
            // IPv6LocalAddressPrefixLength = 0b00100011,
            0b00100011 => PacketFilterComponentType::IPv6LocalAddressPrefixLength,

            // ProtocolIdentifierNextHeader = 0b00110000,
            0b00110000 => PacketFilterComponentType::ProtocolIdentifierNextHeader,
            // SingleLocalPort = 0b01000000,
            0b01000000 => PacketFilterComponentType::SingleLocalPort,
            // LocalPortRange = 0b01000000,
            0b01000000 => PacketFilterComponentType::LocalPortRange,
            // SingleRemotePort = 0b01010000,
            0b01010000 => PacketFilterComponentType::SingleRemotePort,
            // RemotePortRange = 0b01010001,
            0b01010001 => PacketFilterComponentType::RemotePortRange,

            // SecurityParameterIndex = 0b01100000,
            0b01100000 => PacketFilterComponentType::SecurityParameterIndex,
            // TypeOfServiceTrafficClass = 0b01110000,
            0b01110000 => PacketFilterComponentType::TypeOfServiceTrafficClass,
            // FlowLabel = 0b10000000,
            0b10000000 => PacketFilterComponentType::FlowLabel,

            // DestinationMACAddress = 0b10000001,
            0b10000001 => PacketFilterComponentType::DestinationMACAddress,
            // SourceMACAddress = 0b10000010,
            0b10000010 => PacketFilterComponentType::SourceMACAddress,
            // VlanCtagVid = 0b10000011,
            0b10000011 => PacketFilterComponentType::VlanCtagVid,
            // VlanStagVid = 0b10000100,
            0b10000100 => PacketFilterComponentType::VlanStagVid,
            // VlanCtagPcpdei = 0b10000101,
            0b10000101 => PacketFilterComponentType::VlanCtagPcpdei,
            // VlanStagPcpdei = 0b10000110,
            0b10000110 => PacketFilterComponentType::VlanStagPcpdei,
            // Ethertype = 0b10000111,
            0b10000111 => PacketFilterComponentType::Ethertype,
            _ => PacketFilterComponentType::Ethertype,
        }
    }
}
#[derive(Debug,Clone)]
pub enum PacketFilterComponentValue {
    /*For "match-all type", the packet filter component shall not include the packet filter component value field. */
    MatchAll,
    IPv4RemoteAddress(IPv4FilterAddress),
    IPv4LocalAddress(IPv4FilterAddress),
    IPv6RemoteAddressPrefixLength(IPv6FilterAddress),
    IPv6LocalAddressPrefixLength(IPv6FilterAddress),

    ProtocolIdentifierNextHeader(ProtocolIdentifierNextHeader),
    SingleLocalPort(Port),
    LocalPortRange(PortRange),
    SingleRemotePort(Port),
    RemotePortRange(PortRange),

    SecurityParameterIndex(SecurityParameterIndex),
    TypeOfServiceTrafficClass(TypeOfServiceTrafficClass),
    FlowLabel(FlowLabel),

    DestinationMACAddress(MACAddress),
    SourceMACAddress(MACAddress),
    VlanCtagVid(VlanCtagVid),
    VlanStagVid(VlanStagVid),
    VlanCtagPcpdei(VlanCtagPcpdei),
    VlanStagPcpdei(VlanStagPcpdei),
    Ethertype(Ethertype),
    DestinationMACAddressRange(DestinationMACAddressRange),
    SourceMACAddressRange(SourceMACAddressRange),
}

#[derive(Debug,Clone)]

pub struct IPv4FilterAddress {
    /*
     * 对于"IPv4远程/本地地址类型",数据包过滤器组件值字段应编码为
     * 一个四个八位字节的IPv4地址字段和一个四个八位字节的IPv4地址掩码字段序列。
     * IPv4地址字段应首先传输。
     * For "IPv4 remote/local address type", the packet filter component value field shall be encoded as a sequence of a four octet IPv4 address field and a four octet IPv4 address mask field. The IPv4 address field shall be transmitted first.
     */
    ipv4_address: Vec<u8>,
    ipv4_address_mask: Vec<u8>,
}

#[derive(Debug,Clone)]
/*
 * 对于"IPv6远程地址/前缀长度类型",数据包过滤器组件值字段应编码为
 * 一个十六个八位字节的IPv6地址字段和一个八位字节的前缀长度字段序列。
 * IPv6地址字段应首先传输。
 */
pub struct IPv6FilterAddress {
    /* For "IPv6 remote address/prefix length type", the packet filter component value field shall be encoded as a sequence of a sixteen octet IPv6 address field and one octet prefix length field. The IPv6 address field shall be transmitted first.
     */
    ipv6_address: Vec<u8>,
    prefix_length: u8,
}

#[derive(Debug,Clone)]
/*
 * 对于“协议标识符/下一头类型”,数据包过滤器组件值字段应编码为一个八位字节,
 * 该字节指定IPv4协议标识符或IPv6下一头。
 */
pub struct ProtocolIdentifierNextHeader {
    /*For "protocol identifier/Next header type", the packet filter component value field shall be encoded as one octet which specifies the IPv4 protocol identifier or Ipv6 next header. */
    value: u8,
}

#[derive(Debug,Clone)]
pub struct Port {
    /*For "single local port type" and "single remote port type", the packet filter component value field shall be encoded as two octets which specify a port number. */
    value: u16,
}

#[derive(Debug,Clone)]
pub struct PortRange {
    /*For "local port range type" and "remote port range type", the packet filter component value field shall be encoded as a sequence of a two octet port range low limit field and a two octet port range high limit field. The port range low limit field shall be transmitted first. */
    low: u16,
    high: u16,
}

#[derive(Debug,Clone)]
pub struct SecurityParameterIndex {
    /*
     * 对于“安全参数索引”,数据包过滤器组件值字段应编码为四个八位字节,
     * 用于指定IPSec安全参数索引。
     */
    value: u32,
}

#[derive(Debug,Clone)]
pub struct TypeOfServiceTrafficClass {
    /*For "type of service/traffic class type", the packet filter component value field shall be encoded as a sequence of a one octet type-of-service/traffic class field and a one octet type-of-service/traffic class mask field. The type-of-service/traffic class field shall be transmitted first. */
    /*
     * 对于“服务类型/通信类别类型”,数据包过滤器组件值字段应编码为
     * 一个八位字节的服务类型/通信类别字段和一个八位字节的服务类型/通信类别掩码字段序列。
     * 服务类型/通信类别字段应首先传输。
     */
    value: u8,
    mask: u8,
}
#[derive(Debug,Clone)]
pub struct FlowLabel {
    /*For "flow label type", the packet filter component value field shall be encoded as three octets which specify the IPv6 flow label. The bits 8 through 5 of the first octet shall be spare whereas the remaining 20 bits shall contain the IPv6 flow label. */
    /*
     * 对于“流标签类型”,数据包过滤器组件值字段应编码为三个八位字节,
     * 用于指定IPv6流标签。第一个八位字节的第8至5位应为零,其余20位应包含IPv6流标签。
     */
    value: u32,
}
#[derive(Debug,Clone)]
pub struct MACAddress {
    /*For "destination MAC address type" and "source MAC address type", the packet filter component value field shall be encoded as 6 octets which specify a MAC address. When the packet filter direction field indicates "bidirectional", the destination MAC address is the remote MAC address and the source MAC address is the local MAC address. */
    /*
     * 对于“目的MAC地址类型”和“源MAC地址类型”,数据包过滤器组件值字段应编码为6个八位字节,
     * 用于指定一个MAC地址。当数据包过滤器方向字段表示“双向”时,目的MAC地址是远程MAC地址,
     * 源MAC地址是本地MAC地址。
     */
    value: Vec<u8>,
}
#[derive(Debug,Clone)]
pub struct VlanCtagVid {
    /*For "802.1Q C-TAG VID type", the packet filter component value field shall be encoded as two octets which specify the VID of the customer-VLAN tag (C-TAG). The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. If there are more than one C-TAG in the Ethernet frame header, the outermost C-TAG is evaluated.
     */
    // ...
}
#[derive(Debug,Clone)]
pub struct VlanStagVid {
    /*For "802.1Q S-TAG VID type", the packet filter component value field shall be encoded as two octets which specify the VID of the service-VLAN tag (S-TAG). The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. If there are more than one S-TAG in the Ethernet frame header, the outermost S-TAG is evaluated. */
    // ...
}
#[derive(Debug,Clone)]
pub struct VlanCtagPcpdei {
    /*For "802.1Q C-TAG PCP/DEI type", the packet filter component value field shall be encoded as one octet which specifies the 802.1Q C-TAG PCP and DEI. The bits 8 through 5 of the octet shall be spare, the bits 4 through 2 contain the PCP and bit 1 contains the DEI. If there are more than one C-TAG in the Ethernet frame header, the outermost C-TAG is evaluated */
    // ...
}
#[derive(Debug,Clone)]
pub struct VlanStagPcpdei {
    /*For "802.1Q S-TAG PCP/DEI type", the packet filter component value field shall be encoded as one octet which specifies the 802.1Q S-TAG PCP. The bits 8 through 5 of the octet shall be spare, the bits 4 through 2 contain the PCP and bit 1 contains the DEI. If there are more than one S-TAG in the Ethernet frame header, the outermost S-TAG is evaluated */
    // ...
}
#[derive(Debug,Clone)]
pub struct Ethertype {
    /*For "ethertype type", the packet filter component value field shall be encoded as two octets which specify an ethertype */
    // ...
}
#[derive(Debug,Clone)]
pub struct DestinationMACAddressRange {
    /*For "destination MAC address range type", the packet filter component value field shall be encoded as a sequence of a 6 octet destination MAC address range low limit field and a 6 octet destination MAC address range high limit field. The destination MAC address range low limit field shall be transmitted first. When the packet filter direction field indicates "bidirectional", the destination MAC address range is the remote MAC address range. */
    // ...
}
#[derive(Debug,Clone)]
pub struct SourceMACAddressRange {
    /*For "source MAC address range type", the packet filter component value field shall be encoded as a sequence of a 6 octet source MAC address range low limit field and a 6 octet source MAC address range high limit field. The source MAC address range low limit field shall be transmitted first. When the packet filter direction field indicates "bidirectional", the source MAC address is the local MAC address range. */
    // ...
}
impl QOSRules {
    pub fn decode(data: Vec<u8>) -> QOSRules {
        let mut index = 0;
        let length: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;
        let mut qosRulesIEList = HashMap::<u8,QOSRulesIE>::new();
        index += 2; //decoder header
        while index < length.into() {
            // { qosruleidentifer: val, LengthofQoSrule: val, numberofpacketfilters: val, dqrbit: val, ruleoperationcode: val,
            // packetfilterlist: val, qosruleprecedence: val, qosflowidentifer: val, segregation: val, spare: val }
            let qosruleidentifer: u8 = data[index];

            index += 1;
            let LengthofQoSrule: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;

            index += 2;
            // octet 7
            let numberofpacketfilters = data[index] & 0b00001111;
            let dqrbit = (data[index] & 0b00010000) >> 4;
            let ruleoperationcode = RuleOperationCode::from_u8((data[index] & 0b11100000) >> 5);
            index += 1;
            // let mut PacketFilterListEnum { packet_filter_direction, packet_filter_id, length_packet_filter_contents, packet_filter_content_list }
            // let packetFilterListEnum:PacketFilterListEnum =
            let mut packetfilterlist: Vec<PacketFilterListEnum> = vec![];
            for f in 0..numberofpacketfilters{
                let packetfilter: PacketFilterListEnum = match ruleoperationcode {
                    RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters => {
                        //Modify existing QoS rule and delete packet filters
                        //For the "modify existing QoS rule and delete packet filters" operation,
                        //the packet filter list shall contain a variable number of packet filter
                        //identifiers. This number shall be derived from the coding of the number of packet filters field in octet 7
                        let mut packetFilterListDeletePF = PacketFilterListDeletePFList {
                            packet_fliter_id: vec![],
                        };
                        for i in index..(index + numberofpacketfilters as usize) {
                            packetFilterListDeletePF
                                .packet_fliter_id
                                .push(data[index] & 0b00001111);
                            index += 1;
                        }
                        PacketFilterListEnum::PacketFilterListDeletePFList(packetFilterListDeletePF)
                    }
                    RuleOperationCode::DeleteExistingQosRule | RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters => {
                        //Delete existing QoS rule | modify existing QoS rule without modifying packet filters
                        //For the "delete existing QoS rule" operation, the length of QoS rule field is set to one.
                        //For the "delete existing QoS rule" operation and the "modify existing QoS rule without modifying packet filters" operation, the packet filter list shall be empty.
                        PacketFilterListEnum::PacketFilterNone
                    }
                    RuleOperationCode::CreateNewQosRule | 
                    RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters | 
                    RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters => {
                        // Create new QoS rule | Modify existing QoS rule and add packet filters | Modify existing QoS rule and replace all packet filters
                        //For the "create new QoS rule" operation and for the "modify existing
                        //QoS rule and replace all packet filters" operation, the packet filter
                        //list shall contain 0 or a variable number of packet filters. This number
                        //shall be derived from the coding of the number of packet filters field in octet 7
                        // let mut packetFilterListUpdatePFList = PacketFilterListUpdatePFList { packet_filter_direction: {}, packet_filter_id: {}, length_packet_filter_contents: {}, packet_filter_content_list: {} }
                        let packet_filter_direction = pkt_direction::from_u8((data[index] & 0b00110000) >> 4);
                        let packet_filter_id = data[index] & 0b00001111;
                        index += 1;
                        let length_packet_filter_contents = data[index];
                        index += 1;
                   
                        //let mut packetFilterUpdatePF =
                        //PacketFilterListUpdatePFList { packet_filter_direction, packet_filter_id, length_packet_filter_contents, packet_filter_content_list: {} };
                        let mut packet_filter_content_list = Vec::<PacketFilterContent>::new();
                        let b = (index + length_packet_filter_contents as usize) ;
                        while index < b {
                            let filter_content_type = PacketFilterComponentType::from_u8(data[index]);
                            index += 1;
                            let filter_content_value: PacketFilterComponentValue =
                                match filter_content_type {
                                    PacketFilterComponentType::MatchAll => {
                                        PacketFilterComponentValue::MatchAll
                                    }
                                    PacketFilterComponentType::IPv4RemoteAddress => {
                                        let ipv4Address = IPv4FilterAddress {
                                            ipv4_address: data[index..index + 3].to_vec(),
                                            ipv4_address_mask: data[index + 4..index + 7].to_vec(),
                                        };
                                        index += 8;
                                        PacketFilterComponentValue::IPv4RemoteAddress(ipv4Address)
                                    }
                                    PacketFilterComponentType::IPv4LocalAddress => {
                                        let ipv4Address = IPv4FilterAddress {
                                            ipv4_address: data[index..index + 3].to_vec(),
                                            ipv4_address_mask: data[index + 4..index + 7].to_vec(),
                                        };
                                        index += 8;
                                        PacketFilterComponentValue::IPv4LocalAddress(ipv4Address)
                                    }
                                    PacketFilterComponentType::IPv6RemoteAddressPrefixLength => {
                                        let ipv6Address = IPv6FilterAddress {
                                            ipv6_address: data[index..index + 16].to_vec(),
                                            prefix_length: data[index + 16],
                                        };
                                        index += 17;
                                        PacketFilterComponentValue::IPv6RemoteAddressPrefixLength(
                                            ipv6Address,
                                        )
                                    }
                                    PacketFilterComponentType::IPv6LocalAddressPrefixLength => {
                                        let ipv6Address = IPv6FilterAddress {
                                            ipv6_address: data[index..index + 16].to_vec(),
                                            prefix_length: data[index + 16],
                                        };
                                        index += 17;
                                        PacketFilterComponentValue::IPv6LocalAddressPrefixLength(
                                            ipv6Address,
                                        )
                                    }
                                    PacketFilterComponentType::ProtocolIdentifierNextHeader => {
                                        let buf =
                                            PacketFilterComponentValue::ProtocolIdentifierNextHeader(
                                                ProtocolIdentifierNextHeader { value: data[index] },
                                            );
                                        index += 1;
                                        buf
                                    }
                                    PacketFilterComponentType::SingleLocalPort => {
                                        let port: u16 =
                                            (data[index] as u16) << 8 | data[index + 1] as u16;
                                        index += 2;
                                        PacketFilterComponentValue::SingleLocalPort(Port {
                                            value: port,
                                        })
                                    }
                                    PacketFilterComponentType::LocalPortRange => {
                                        let port_low: u16 =
                                            (data[index] as u16) << 8 | data[index + 1] as u16;
                                        let port_high: u16 =
                                            (data[index + 2] as u16) << 8 | data[index + 3] as u16;
                                        index += 4;
                                        PacketFilterComponentValue::LocalPortRange(PortRange {
                                            low: port_low,
                                            high: port_high,
                                        })
                                    }
                                    PacketFilterComponentType::SingleRemotePort => {
                                        let port: u16 =
                                            (data[index] as u16) << 8 | data[index + 1] as u16;
                                        index += 2;
                                        PacketFilterComponentValue::SingleRemotePort(Port {
                                            value: port,
                                        })
                                    }
                                    PacketFilterComponentType::RemotePortRange => {
                                        let port_low: u16 =
                                            (data[index] as u16) << 8 | data[index + 1] as u16;
                                        let port_high: u16 =
                                            (data[index + 2] as u16) << 8 | data[index + 3] as u16;
                                        index += 4;
                                        PacketFilterComponentValue::RemotePortRange(PortRange {
                                            low: port_low,
                                            high: port_high,
                                        })
                                    }
                                    PacketFilterComponentType::SecurityParameterIndex => {
                                        // let para:u32 =  (data[index] as u32) << 24 | data[index + 1] as u16| data[index + 2] as u16| data[index + 3] as u16;
                                        index += 4;
                                        PacketFilterComponentValue::SecurityParameterIndex(
                                            SecurityParameterIndex { value: 0 },
                                        )
                                    }
                                    PacketFilterComponentType::TypeOfServiceTrafficClass => {
                                        index += 2;
                                        PacketFilterComponentValue::TypeOfServiceTrafficClass(
                                            TypeOfServiceTrafficClass { value: 0, mask: 0 },
                                        )
                                    }
                                    PacketFilterComponentType::FlowLabel => {
                                        index += 3;
                                        PacketFilterComponentValue::FlowLabel(FlowLabel { value: 0 })
                                    }
                                    PacketFilterComponentType::DestinationMACAddress => {
                                        index += 6;
                                        PacketFilterComponentValue::DestinationMACAddress(MACAddress {
                                            value: vec![0u8, 0, 0, 0, 0, 0],
                                        })
                                    }
                                    PacketFilterComponentType::SourceMACAddress => {
                                        index += 6;
                                        PacketFilterComponentValue::SourceMACAddress(MACAddress {
                                            value: vec![0u8, 0, 0, 0, 0, 0],
                                        })
                                    }
                                    PacketFilterComponentType::VlanCtagVid => {
                                        index += 2;
                                        PacketFilterComponentValue::VlanCtagVid(VlanCtagVid {})
                                    }
                                    PacketFilterComponentType::VlanStagVid => {
                                        index += 2;
                                        PacketFilterComponentValue::VlanStagVid(VlanStagVid {})
                                    }
                                    PacketFilterComponentType::VlanCtagPcpdei => {
                                        index += 1;
                                        PacketFilterComponentValue::VlanCtagPcpdei(VlanCtagPcpdei {})
                                    }
                                    PacketFilterComponentType::VlanStagPcpdei => {
                                        index += 1;
                                        PacketFilterComponentValue::VlanStagPcpdei(VlanStagPcpdei {})
                                    }
                                    PacketFilterComponentType::Ethertype => {
                                        index += 2;
                                        PacketFilterComponentValue::Ethertype(Ethertype {})
                                    }
                                
                                };
                            packet_filter_content_list.push(PacketFilterContent {
                                packet_filter_content_type: filter_content_type,
                                packet_filter_content_value: filter_content_value,
                            });
                        }
                        PacketFilterListEnum::PacketFilterListUpdatePFList(
                            PacketFilterListUpdatePFList {
                                packet_filter_direction: packet_filter_direction,
                                packet_filter_id: packet_filter_id,
                                length_packet_filter_contents: length_packet_filter_contents,
                                packet_filter_content_list: packet_filter_content_list,
                            },
                        )
                    }

                    _ => PacketFilterListEnum::PacketFilterNone,
                };
                packetfilterlist.push(packetfilter.clone());
        }
                //  println!("{:#?}",index);
                // let mut q_osrules_ie = QOSRulesIE::
                let mut qosruleprecedence = 0u8;
                let mut qosflowidentifer = 0u8;
                let mut segregation = 0u8;
                let mut spare = 0u8;
                match ruleoperationcode {
                    RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters => {
                        //Modify existing QoS rule and delete packet filters
                        //For the "modify existing QoS rule and delete packet filters" operation,
                        //the packet filter list shall contain a variable number of packet filter
                        //identifiers. This number shall be derived from the coding of the number of packet filters field in octet 7
                        
                    }
                    RuleOperationCode::DeleteExistingQosRule | RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters => {
                        //Delete existing QoS rule | modify existing QoS rule without modifying packet filters
                        //For the "delete existing QoS rule" operation, the length of QoS rule field is set to one.
                        //For the "delete existing QoS rule" operation and the "modify existing QoS rule without modifying packet filters" operation, the packet filter list shall be empty.
                        
                    }
                    RuleOperationCode::CreateNewQosRule | 
                    RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters | 
                    RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters => {
                        // Create new QoS rule | Modify existing QoS rule and add packet filters | Modify existing QoS rule and replace all packet filters
                        //For the "create new QoS rule" operation and for the "modify existing
                        //QoS rule and replace all packet filters" operation, the packet filter
                        //list shall contain 0 or a variable number of packet filters. This number
                        //shall be derived from the coding of the number of packet filters field in octet 7
                        // let mut packetFilterListUpdatePFList = PacketFilterListUpdatePFList { packet_filter_direction: {}, packet_filter_id: {}, length_packet_filter_contents: {}, packet_filter_content_list: {} }
                        qosruleprecedence = data[index];
                        index += 1;
                        qosflowidentifer = data[index] & 0b00111111;
                        segregation = data[index] & 0b01000000;
                        spare = 0u8;
                        index += 1;
                        
                    },

                    _ => {
                        
                    },
                };

                let q_osrules_ie = QOSRulesIE {
                    qosruleidentifer,
                    lengthof_qo_srule: LengthofQoSrule,
                    numberofpacketfilters,
                    dqrbit,
                    ruleoperationcode,
                    packetfilterlist,
                    qosruleprecedence,
                    qosflowidentifer,
                    segregation,
                    spare,
                };

            qosRulesIEList.insert(qosruleidentifer,q_osrules_ie);
        }
        
        // println!("{:#?}",length);
        QOSRules {
            lengthofqosrulesie: length,
            qosrulesie: qosRulesIEList,
        }
    }
}