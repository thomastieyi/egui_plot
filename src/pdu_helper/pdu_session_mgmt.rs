use crate::{
    msg,
    pdu_helper::{
        pdu_accept::{
            ExtProtoCfgOpts, PDUAddress, PDUSessionType, PduAddressType,
            PduSessionEstablishmentAcceptMsg, QOSFlowDescriptions, SSCMode, DNN,
        },
        pdu_helper::{
            ExtendedProtocolDiscriminator, PDUSessionIdentity, PduSessionPlainMsg,
            ProcedureTransactionIdentity, SessionMessageType,
        },
        qos_rules::{self, QOSRules, QOSRulesIE},
    },
    route_helper::{RouteCmd, RouteCmdKind},
};
use ::gtp_rs::gtpv1::gtpu::*;

use encoding::all::GBK;
use encoding::{all::GB18030, DecoderTrap, Encoding};
use log::{debug, error, info, trace, warn};
use pnet::packet::{icmpv6::checksum, MutablePacket};
use pnet::packet::{
    icmpv6::{ndp::MutableRouterSolicitPacket, Icmpv6Code, Icmpv6Packet, Icmpv6Types},
    ip::IpNextHeaderProtocols,
    ipv6::MutableIpv6Packet,
    Packet,
};
use std::{
    collections::HashMap,
    f32::consts::E,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossbeam::{
    channel::{unbounded, Receiver, Sender},
    queue::{ArrayQueue, SegQueue},
};
use msg::IttiMsg;
use subprocess::{Popen, PopenConfig, Redirection};
use wintun::{Adapter, Session};


fn pdu_session_modify_qos(mut qosrules : QOSRules, qos_to_add_mod_list: HashMap<u8, QOSRulesIE>) {
    for qos_rules_ie in qos_to_add_mod_list {
        match qos_rules_ie.1.ruleoperationcode {
            qos_rules::RuleOperationCode::Reserved => {}
            qos_rules::RuleOperationCode::CreateNewQosRule => {
                if !qosrules.qosrulesie.contains_key(&qos_rules_ie.0) {
                    qosrules
                        .qosrulesie
                        .insert(qos_rules_ie.0.clone(), qos_rules_ie.1.clone());
                }
            }
            qos_rules::RuleOperationCode::DeleteExistingQosRule => {
                if qosrules.qosrulesie.contains_key(&qos_rules_ie.0) {
                    qosrules.qosrulesie.remove(&qos_rules_ie.0.clone());
                }
            }
            qos_rules::RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters => {}
            qos_rules::RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters => {}
            qos_rules::RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters => {}
            qos_rules::RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters => {}
        }
    }
    let mut buffer = Vec::with_capacity(1500 + 14);
    buffer.resize(1500 + 14, 0u8);
    let mut test_pkt = MutableIpv6Packet::new(&mut buffer).unwrap();
    let a: [u8; 16] = [36u8, 14, 0, 102, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 37];
    let dest = Ipv6Addr::from(a);
    test_pkt.set_destination(dest);
    test_pkt.set_version(6);
    // println!("{}",self.qosrules.reflect_pkt_to_qfi(buffer.clone()));

    // let mut buffer = Vec::with_capacity(1500 + 14);
    // buffer.resize(1500 + 14, 0u8);
    // let mut test_pkt = MutableIpv6Packet::new(&mut buffer).unwrap();
    // let a: [u8; 16] = [36u8, 14, 0, 102, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 31];
    // let dest = Ipv6Addr::from(a);
    // test_pkt.set_destination(dest);
    // test_pkt.set_version(6);
    // println!("{}",self.qosrules.reflect_pkt_to_qfi(buffer.clone()));
}


#[derive(Clone)]
pub struct PduSessionMgmt {
    pub pdu_sessions: Arc<RwLock<HashMap<PDUSessionIdentity, PduSession>>>,
    pub trx: (Sender<i32>, Receiver<i32>),
    pub global_queue: Arc<SegQueue<IttiMsg>>,
    pub global_udp_tx_queue: Arc<ArrayQueue<Vec<u8>>>,
    pub global_udp_rx_queue: Arc<ArrayQueue<Vec<u8>>>,
}
impl PduSessionMgmt {
    pub fn default(
        g_m: Arc<SegQueue<IttiMsg>>,
        tx: Arc<ArrayQueue<Vec<u8>>>,
        rx: Arc<ArrayQueue<Vec<u8>>>,
    ) -> PduSessionMgmt {
        PduSessionMgmt {
            pdu_sessions: Arc::new(RwLock::new(HashMap::<PDUSessionIdentity, PduSession>::new())),
            trx: unbounded(),
            global_queue: g_m,
            global_udp_tx_queue: tx.clone(),
            global_udp_rx_queue: rx.clone(),
        }
    }

    pub fn init_pdu_session_mgmt_task(
        mut self,
        itti_msg_trx: (Sender<IttiMsg>, Receiver<IttiMsg>),
    ) {
        let global_udp_rx_queue_for_mgmt = self.global_udp_rx_queue.clone();
        let self_clone = self.pdu_sessions.clone();

        thread::spawn(move || loop {
            match global_udp_rx_queue_for_mgmt.pop() {
                Some(byte) => {
                    // println!("gtp {:?}",byte);
                    // let _ = socket.send_to(&byte, addr);
                    let mut time_in = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards");
                    match Gpdu::unmarshal(&byte) {
                        Ok(gpdu) => {
                            let pdu_id: u8 = ((gpdu.header.teid
                                & 0b00000000_00000000_11111111_00000000)
                                >> 8) as u8;
                            let qfi: u8 = ((gpdu.header.teid
                                & 0b00000000_00000000_00000000_11111111)
                                >> 8) as u8;
                            {
                                loop {
                                    let b = self_clone.try_read();
                                    match b {
                                        Ok(mut b) => {
                                            //get pdu_entity
                                            match b.get(&pdu_id) {
                                                Some(pdu_entity) => {
                                                    pdu_entity
                                                        .local_udp_rx_queue
                                                        .force_push(gpdu.tpdu.clone());
                                                }
                                                None => {
                                                    println!("None pdu find");
                                                }
                                            };
                                            break;
                                        }
                                        Err(_) => {
                                            println!("None pdu find continue");
                                            continue;
                                        }
                                    }
                                }
                            }
                            // println!("{:?}", self_clone.capacity());
                            // match self_clone.get(&pdu_id) {
                            //     Some(pdu_entity) => {
                            //         println!("{:?}", gpdu.tpdu);

                            //         pdu_entity.local_udp_rx_queue.push(gpdu.tpdu);
                            //     },
                            //     None => {

                            //     },
                            // };
                        }
                        Err(e) => {
                            println!("{:?}", e);
                        }
                    };
                    let mut time_out = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards");
                    trace!(
                        "GTP_U Decode {:?} : Time Stemp {:?}",
                        time_out - time_in,
                        time_in
                    );
                }
                None => {
                    thread::sleep(Duration::from_micros(10));

                }
            }
        });

        loop {
            match itti_msg_trx.1.recv() {
                Ok(msg) => {
                    match msg {
                        IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg(plain_nas5_gsmessage) => {
                            match plain_nas5_gsmessage {
                                PduSessionPlainMsg::EstablishmentAccept(accept_msg) => {
                                    let mut pdu_entity = PduSession::init_from_accept_msg(
                                        accept_msg.clone(),
                                        self.global_udp_tx_queue.clone(),
                                        Arc::new(ArrayQueue::<Vec<u8>>::new(3000)),
                                    );
                                    let socket = UdpSocket::bind(format!("0.0.0.0:0")).expect(" Failed to bind socket");
                                    socket.set_nonblocking(true).unwrap();
                                    let addr = format!("127.0.0.1:2222");
                                    if(accept_msg.clone().get_dnn_name() == "ims") {
                                        debug!("{:#?}", accept_msg.clone().get_pcscf_v6_address());
                                        let _ = socket.send_to(accept_msg.clone().get_pcscf_v6_address().to_string().as_bytes(), &addr);
                                    } 
                                    {
                                        loop {
                                            let bb = self.pdu_sessions.try_write();
                                            match bb {
                                                Ok(mut b) => {
                                                    b.insert(
                                                        pdu_entity.pdusessionidentity.clone(),
                                                        pdu_entity.clone(),
                                                    );

                                                    // global_itti_trx_tag_list_pdu.
                                                    break;
                                                }
                                                Err(_) => {
                                                    continue;
                                                }
                                            }
                                        }
                                    }

                                    pdu_entity.run();
                                    // println!("{:#?}", accept_msg.clone());
                                }
                                PduSessionPlainMsg::DeletePduSession(pduId) => loop {
                                    let b = self.pdu_sessions.try_write();
                                    match b {
                                        Ok(mut b) => {
                                            match b.get(&pduId) {
                                                Some(pdu_entity) => {
                                                    pdu_entity.destory();
                                                    drop(pdu_entity);
                                                    b.remove(&pduId);
                                                }
                                                None => {}
                                            };
                                            break;
                                        }
                                        Err(_) => {
                                            continue;
                                        }
                                    }
                                },
                                PduSessionPlainMsg::ModificationCommand(modify_msg) => {
                                    {
                                        
                                        loop {
                                            let b = self.pdu_sessions.try_write();
                                            match b {
                                                Ok(mut b) => {
                                                    //get pdu id
                                                    debug!("TASK MODIFY");

                                                    let mut pdu_id: u8 =
                                                        modify_msg.pdusessionidentity;
                                                    //get pdu_entity
                                                    match b.get(&pdu_id) {
                                                        Some(pdu_entity) => {
                                                            pdu_entity.trx.0.send(PduEntityMsg::QosRulesMsg(modify_msg
                                                                .qosrules
                                                                .qosrulesie
                                                                .clone()));
                                                            //get qos to modify
                                                            // pdu_session_modify_qos(
                                                            //         pdu_entity.clone().qosrules,
                                                                    
                                                            //     );
                                                                debug!("Modify PDU_ID {:?}", pdu_entity.clone().get_dnn_name());
                                                                debug!("Modify Rules {:#?}", pdu_entity.clone().qosrules);
                                                        }
                                                        None => {}
                                                    };

                                                    break;
                                                }
                                                Err(_) => {
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                                PduSessionPlainMsg::DeleteAllPduSessions => loop {
                                    let b = self.pdu_sessions.try_write();
                                    match b {
                                        Ok(mut b) => {
                                            let keys = b.keys().clone();
                                            for pduId in keys {
                                                match b.get(&pduId) {
                                                    Some(pdu_entity) => {
                                                        pdu_entity.destory();
                                                        drop(pdu_entity);
                                                    }
                                                    None => todo!(),
                                                };
                                            }
                                            b.clear();
                                            break;
                                        }
                                        Err(_) => {
                                            continue;
                                        }
                                    }
                                },
                            }
                        }
                        // IttiMsg::PduSessionMgmtModifiyPduSession(plain_nas5_gsmessage) => {

                        // },
                        // IttiMsg::PduSessionMgmtDestoryPduSession(plain_nas5_gsmessage) => {

                        //     self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                        // let a = &self.pdu_sessions[0];
                        // a.destory(self.trx.clone());
                        // drop(a);
                        // },
                        _ => {
                            info!("{:#?}", msg);
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
}

#[derive(Clone)]
pub enum PduEntityMsg {
    DestoryMsg(i32),
    QosRulesMsg(HashMap<u8, QOSRulesIE>)
}
#[derive(Clone)]
pub struct PduSession {
    pub extendedprotocoldiscriminator: ExtendedProtocolDiscriminator,
    pub pdusessionidentity: PDUSessionIdentity,
    pub proceduretransactionidentity: ProcedureTransactionIdentity,
    pub messagetype: SessionMessageType,
    pub pdusessiontype: PDUSessionType,
    pub sscmode: SSCMode,
    /**
    1. 维护pdu实体的QoS实体,
    2. 负责QoS QFI映射,
    */
    pub qosrules:Arc<RwLock<QOSRules>> ,
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
    pub trx: (Sender<PduEntityMsg>, Receiver<PduEntityMsg>),
    /**
    1. reader_session,
    2. writer_session,
    3. wintun_adapter_index,
    4. adapter,
    */
    pub tun_trx_index: (Arc<Session>, Arc<Session>, u32, Arc<Adapter>),
    /**
     * 全局GTP-U/UDP发送队列
     */
    pub global_udp_tx_queue: Arc<ArrayQueue<Vec<u8>>>,
    /**
     * 私有GTP-U/UDP接受队列，下行数据包，由Mgmt管理
     */
    pub local_udp_rx_queue: Arc<ArrayQueue<Vec<u8>>>,
}

impl PduSession {
    pub fn init_from_accept_msg(
        mut accept_msg: PduSessionEstablishmentAcceptMsg,
        tx: Arc<ArrayQueue<Vec<u8>>>,
        rx: Arc<ArrayQueue<Vec<u8>>>, // trx: (Sender<i32>, Receiver<i32>),
    ) -> PduSession {
        PduSession {
            trx: unbounded(),
            extendedprotocoldiscriminator: accept_msg.clone().extendedprotocoldiscriminator,
            pdusessionidentity: accept_msg.clone().pdusessionidentity,
            proceduretransactionidentity: accept_msg.clone().proceduretransactionidentity,
            messagetype: accept_msg.clone().messagetype,
            pdusessiontype: accept_msg.clone().pdusessiontype,
            sscmode: accept_msg.clone().sscmode,
            qosrules: Arc::new(RwLock::new(accept_msg.clone().qosrules)),
            pduaddress: accept_msg.clone().pduaddress,
            qosflowdescriptions: accept_msg.clone().qosflowdescriptions,
            extendedprotocolconfigurationoptions: accept_msg
                .clone()
                .extendedprotocolconfigurationoptions,
            dnn: accept_msg.clone().dnn,
            tun_trx_index: Self::init_tun(accept_msg.clone().get_dnn_name()),
            global_udp_tx_queue: tx.clone(),
            local_udp_rx_queue: rx.clone(),
        }
    }

    pub fn run(mut self) {
        let running = Arc::new(AtomicBool::new(true));
        let running_flag_for_msg = running.clone();
        let running_ul = running.clone();
        let running_dl = running.clone();
        let tun_trx_ul = self.tun_trx_index.clone();
        let tun_trx_dl = self.tun_trx_index.clone();
        let tun_trx_mgmt = self.tun_trx_index.clone();
        let (gtp_u_tx, gtp_u_rx) = unbounded::<Vec<u8>>(); // TBD
        self.set_ipv4();
        let mut has_v6 = match self.get_ipv6() {
            Ok(_) => true,
            Err(_) => false,
        };
        let ul_sender = Arc::new(gtp_u_tx.clone());
        let dl_reciver = Arc::new(gtp_u_rx.clone());
        let qos_rules_ = self.qosrules.clone();
        info!("pdu id{:#?}", self.pdusessionidentity);
        // println!("pdu v4 addr{} ", self.get_ipv4().unwrap());
        // println!("pdu id{:#?}", self.pduaddress.pdu_address_information.dnn_to_string());
        info!("pdu winindex {:#?}", self.tun_trx_index.2);
        thread::spawn(move || loop {
            match self.trx.1.recv() {
                Ok(i) => {
                    match i {
                        PduEntityMsg::DestoryMsg(msg) => {
                            running_flag_for_msg.store(false, Ordering::Relaxed);
                        // self.tun_trx_index.0.shutdown();
                        // self.tun_trx_index.1.shutdown();
                        // drop(self.tun_trx_index.3.clone())
                        },
                        PduEntityMsg::QosRulesMsg(qos_to_add_mod_list) => {
                            for qos_rules_ie in qos_to_add_mod_list {
                                match qos_rules_ie.1.ruleoperationcode {
                                    qos_rules::RuleOperationCode::Reserved => {}
                                    qos_rules::RuleOperationCode::CreateNewQosRule => {
                                        loop {
                                            let bb = qos_rules_.try_write();
                                            match bb {
                                                Ok(mut qosrules) => {
                                                    if !qosrules.qosrulesie.contains_key(&qos_rules_ie.0) {
                                                        qosrules
                                                            .qosrulesie
                                                            .insert(qos_rules_ie.0.clone(), qos_rules_ie.1.clone());
                                                    }
                    
                                                    // global_itti_trx_tag_list_pdu.
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                        }
                                        
                                        
                                    }
                                    qos_rules::RuleOperationCode::DeleteExistingQosRule => {
                                        loop {
                                            let bb = qos_rules_.try_write();
                                            match bb {
                                                Ok(mut qosrules) => {
                                                    if qosrules.qosrulesie.contains_key(&qos_rules_ie.0) {
                                                    qosrules.qosrulesie.remove(&qos_rules_ie.0.clone());
                                                    }
                                                    // global_itti_trx_tag_list_pdu.
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                        }

                                        
                                    }
                                    qos_rules::RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters => {}
                                    qos_rules::RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters => {}
                                    qos_rules::RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters => {}
                                    qos_rules::RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters => {}
                                }
                            }
                        },
                    }
                    
                }
                Err(_) => {
                }
            }
        });
        thread::spawn(move || {
            let mut v6_cnt = 0;
            while running_ul.load(Ordering::Relaxed) {
                if has_v6 && v6_cnt % 5000 == 0 {
                    let mut buffer: Vec<u8> = vec![];
                    let mut send_header = Gtpv1Header::default();
                    send_header.msgtype = GPDU;
                    // send_header.sequence_number = Some(2000);
                    //pdu_id | qfi
                    //to simplify
                    let mut qfi = 1;
                    let mut packet = build_icmpv6_router_solicit_ipv6_packet();
                    loop {
                        let b = self.qosrules.try_read();
                        match b {
                            Ok(mut qosrules) => {
                                //get pdu_entity
                                qfi = qosrules.reflect_pkt_to_qfi(packet.clone());

                                break;
                            }
                            Err(_) => {
                                // println!("None pdu find continue");
                                continue;
                            }
                        }
                    }
                    send_header.teid =
                        (((self.pdusessionidentity as u32) << 8) | qfi as u32) as u32;
                    // send_header.extension_headers =
                    // Some(vec![ExtensionHeader::PduSessionContainer(PduSessionContainer {
                    //     extension_header_type: PDU_SESSION_CONTAINER,
                    //     length: 2,
                    //     container: vec![0, 1, 2, 3, 4, 5],
                    // })]);
                    let mut message = Gpdu::default();
                    message.header = send_header;
                    message.tpdu = packet;
                    message.marshal(&mut buffer);
                    self.global_udp_tx_queue.push(buffer);
                }

                // 循环接收并响应数据包，上行数据包
                match tun_trx_ul.0.receive_blocking() {
                    Ok(mut packet) => {
                        let mut buffer: Vec<u8> = vec![];
                        let mut send_header = Gtpv1Header::default();
                        send_header.msgtype = GPDU;
                        // send_header.sequence_number = Some(2000);
                        //pdu_id | qfi
                        //to simplify
                        let mut time_in = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards");
                        // debug!("{:#?}",self.qosrules);
                        let mut qfi =1;
                        loop {
                            let b = self.qosrules.try_read();
                            match b {
                                Ok(mut qosrules) => {
                                    //get pdu_entity
                                    qfi = qosrules.reflect_pkt_to_qfi(packet.bytes().to_vec());
    
                                    break;
                                }
                                Err(_) => {
                                    // println!("None pdu find continue");
                                    continue;
                                }
                            }
                        }
 
                        let mut time_out = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards");
                        // debug!("qfi reflect time: {:?}", time_out - time_in);

                        time_in = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards");

                        send_header.teid =
                            (((self.pdusessionidentity as u32) << 8) | qfi as u32) as u32;
                        // send_header.extension_headers =
                        // Some(vec![ExtensionHeader::PduSessionContainer(PduSessionContainer {
                        //     extension_header_type: PDU_SESSION_CONTAINER,
                        //     length: 2,
                        //     container: vec![0, 1, 2, 3, 4, 5],
                        // })]);
                        let mut message = Gpdu::default();
                        message.header = send_header;
                        message.tpdu = packet.bytes().to_vec();
                        message.marshal(&mut buffer);
                        self.global_udp_tx_queue.push(buffer);

                        time_out = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards");
                        // debug!("gtp_u construct: {:?}", time_out - time_in);

                        v6_cnt += 1;
                        v6_cnt = v6_cnt % 10000;
                        // println!("pdu {:?}",packet.bytes());//QoS Flow Reflection
                    }
                    Err(err) => {
                        warn!("TX Session Shutdwon: {:?}", err);
                        break;
                    } // }
                }
            }
            // println!("{:#?}",running2);
            warn!("PDU {:?} TX (UL Data) destoryed", self.pdusessionidentity);
        });
        thread::spawn(move || {
            while running_dl.load(Ordering::Relaxed) {
                match self.local_udp_rx_queue.pop() {
                    Some(packet) => {
                        let mut byte = tun_trx_dl
                            .1
                            .allocate_send_packet(packet.len().try_into().unwrap())
                            .unwrap();
                        byte.bytes_mut().copy_from_slice(&packet);
                        tun_trx_dl.0.send_packet(byte);
                        // println!("gtp tpdu {:?}", packet);
                        // let _ = socket.send_to(&byte, addr);
                    }
                    None => {
                        thread::sleep(Duration::from_micros(1));

                    }
                }

                // println!("{:#?}",running2);
            }
            warn!("PDU {:?} RX (DL Data) destoryed", self.pdusessionidentity);
        });
        // drop(self.tun_trx_index);
    }
    pub fn destory(&self) {
        self.trx.0.send(PduEntityMsg::DestoryMsg(1));
    }


}

/**
 * 相关IP、DNN操作实现
 */
impl PduSession {
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

    pub fn get_ipv6(&mut self) -> Result<IpAddr, &str> {
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

impl PduSession {
    /**
       1. reader_session,
       2. writer_session,
       3. wintun_adapter_index,
       4. adapter,
    */

    pub fn init_tun(dnn: String) -> (Arc<Session>, Arc<Session>, u32, Arc<Adapter>) {
        let wintun =
            unsafe { wintun::load_from_path("wintun.dll") }.expect("Failed to load wintun dll");
        // let  str1 = pduData.dnn.to_string().clone();
        let adapter: Arc<wintun::Adapter> = match wintun::Adapter::open(&wintun, &dnn.clone()) {
            Ok(a) => a,
            Err(_) => match wintun::Adapter::create(&wintun, &dnn.clone(), &dnn.clone(), None) {
                Ok(d) => d,
                Err(err) => {
                    panic!("{:#?}", err)
                }
            },
        };
        // let version = wintun::get_running_driver_version(&wintun).unwrap();
        //完成创建，获取IF Index
        info!("{:#?}", dnn);
        let wintun_adapter_index = adapter
            .get_adapter_index()
            .expect("Failed to get adapter index");

        let main_session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .expect("Failed to create session"),
        );
        let reader_session: Arc<wintun::Session> = main_session.clone();
        let writer_session: Arc<wintun::Session> = main_session.clone();
        (
            reader_session,
            writer_session,
            wintun_adapter_index,
            adapter.clone(),
        )
    }
    pub fn set_ipv4(&mut self) {
        match self.pdusessiontype.pdu_session_type_value {
            PduAddressType::IPV4 | PduAddressType::IPV4V6 => {
                let ipv4 = self.get_ipv4();
                match ipv4 {
                    Ok(ip) => {
                        let mut routes: Vec<RouteCmd> = Vec::new();
                        // //设置网卡Metric
                        routes.push(RouteCmd::set(format!(
                            "interface {} mtu 1450 metric=10",
                            self.tun_trx_index.2
                        )));
                        // //设置ip地址
                        routes.push(RouteCmd::set(format!(
                            "address {} static {}/{} store=active",
                            self.tun_trx_index.2, ip, "24"
                        )));
                        routes.push(RouteCmd::set(format!(
                            "dnsservers {} static {} register=primary validate=no",
                            self.tun_trx_index.2, "8.8.8.8"
                        )));
                        routes.push(RouteCmd::add(format!(
                            "route 0.0.0.0/0 {} store=active metric=10",
                            self.tun_trx_index.2,
                        )));
                        for route in &routes {
                            let mut args: Vec<String> = Vec::new();
                            args.push("netsh".to_owned());
                            args.push("interface".to_owned());
                            args.push("ip".to_owned());
                            args.push(
                                match route.kind {
                                    RouteCmdKind::Add => "add",
                                    RouteCmdKind::Set => "set",
                                    RouteCmdKind::Delete => "delete",
                                }
                                .to_owned(),
                            );
                            args.extend(route.cmd.split(' ').map(|arg| arg.to_owned()));
                            let mut result = Popen::create(
                                args.as_slice(),
                                PopenConfig {
                                    stdout: Redirection::Pipe,
                                    stderr: Redirection::Merge,
                                    ..Default::default()
                                },
                            )
                            .expect("Failed to run cmd");

                            let raw_output = result
                                .communicate(None)
                                .expect("Failed to get output from process")
                                .0
                                .unwrap();

                            let _output: &str = raw_output.trim();
                            let _status = result.wait().expect("Failed to get process exit status");
                        }
                    }
                    Err(_) => {}
                }
            }
            PduAddressType::IPV6 => {
                let mut routes: Vec<RouteCmd> = Vec::new();
                // //设置网卡Metric
                routes.push(RouteCmd::set(format!(
                    "address {} source=dhcp address=none gateway=none",
                    self.tun_trx_index.2
                )));
                //运�?�命�?
                for route in &routes {
                    let mut args: Vec<String> = Vec::new();
                    args.push("netsh".to_owned());
                    args.push("interface".to_owned());
                    args.push("ip".to_owned());
                    args.push(
                        match route.kind {
                            RouteCmdKind::Add => "add",
                            RouteCmdKind::Set => "set",
                            RouteCmdKind::Delete => "delete",
                        }
                        .to_owned(),
                    );
                    args.extend(route.cmd.split(' ').map(|arg| arg.to_owned()));
                    let mut result = Popen::create(
                        args.as_slice(),
                        PopenConfig {
                            stdout: Redirection::Pipe,
                            stderr: Redirection::Merge,
                            ..Default::default()
                        },
                    )
                    .expect("Failed to run cmd");

                    let raw_output = result
                        .communicate(None)
                        .expect("Failed to get output from process")
                        .0
                        .unwrap();

                    let _output: &str = raw_output.trim();
                    let _status = result.wait().expect("Failed to get process exit status");
                }
            }
            PduAddressType::Unknown => {}
        }
    }
    pub fn set_ipv6(&mut self) {
        match self.pdusessiontype.pdu_session_type_value {
            PduAddressType::IPV6 | PduAddressType::IPV4V6 => {
                let ipv6 = self.get_ipv6();
                match ipv6 {
                    Ok(ip) => {
                        let mut routes: Vec<RouteCmd> = Vec::new();
                        // //设置网卡Metric
                        routes.push(RouteCmd::set(format!(
                            "interface {} metric=5000",
                            self.tun_trx_index.2
                        )));
                        // //设置ip地址
                        routes.push(RouteCmd::set(format!(
                            "address {} static {}/{} store=active",
                            self.tun_trx_index.2, ip, "24"
                        )));
                        routes.push(RouteCmd::set(format!(
                            "dnsservers {} static {} register=primary validate=no",
                            self.tun_trx_index.2, "8.8.8.8"
                        )));
                        // routes.push(RouteCmd::add(format!(
                        //     "route 0.0.0.0/0 {} store=active metric=10",
                        //     self.tun_trx_index.2,
                        // )));
                        for route in &routes {
                            let mut args: Vec<String> = Vec::new();
                            args.push("netsh".to_owned());
                            args.push("interface".to_owned());
                            args.push("ip".to_owned());
                            args.push(
                                match route.kind {
                                    RouteCmdKind::Add => "add",
                                    RouteCmdKind::Set => "set",
                                    RouteCmdKind::Delete => "delete",
                                }
                                .to_owned(),
                            );
                            args.extend(route.cmd.split(' ').map(|arg| arg.to_owned()));
                            let mut result = Popen::create(
                                args.as_slice(),
                                PopenConfig {
                                    stdout: Redirection::Pipe,
                                    stderr: Redirection::Merge,
                                    ..Default::default()
                                },
                            )
                            .expect("Failed to run cmd");

                            let raw_output = result
                                .communicate(None)
                                .expect("Failed to get output from process")
                                .0
                                .unwrap();

                            let _output: &str = raw_output.trim();
                            let _status = result.wait().expect("Failed to get process exit status");
                        }
                    }
                    Err(_) => {}
                }
            }
            PduAddressType::IPV4 => {
                let mut routes: Vec<RouteCmd> = Vec::new();
                // //设置网卡Metric
                routes.push(RouteCmd::set(format!(
                    "address {} source=dhcp address=none gateway=none",
                    self.tun_trx_index.2
                )));
                for route in &routes {
                    let mut args: Vec<String> = Vec::new();
                    args.push("netsh".to_owned());
                    args.push("interface".to_owned());
                    args.push("ip".to_owned());
                    args.push(
                        match route.kind {
                            RouteCmdKind::Add => "add",
                            RouteCmdKind::Set => "set",
                            RouteCmdKind::Delete => "delete",
                        }
                        .to_owned(),
                    );
                    args.extend(route.cmd.split(' ').map(|arg| arg.to_owned()));
                    let mut result = Popen::create(
                        args.as_slice(),
                        PopenConfig {
                            stdout: Redirection::Pipe,
                            stderr: Redirection::Merge,
                            ..Default::default()
                        },
                    )
                    .expect("Failed to run cmd");

                    let raw_output = result
                        .communicate(None)
                        .expect("Failed to get output from process")
                        .0
                        .unwrap();

                    let _output: &str = raw_output.trim();
                    let _status = result.wait().expect("Failed to get process exit status");
                }
            }
            PduAddressType::Unknown => {}
        }
    }
}

impl PduSession {



}

// 构建 ICMPv6 Router Solicitation 扩展头部数据包
fn build_icmpv6_router_solicit_ipv6_packet() -> Vec<u8> {
    // 分配 ICMPv6 包和 IPv6 头部缓冲区
    let mut icmpv6_buf = [0u8; 8];
    let mut ip_buf = [0u8; 48];

    // 构建可变 ICMPv6 Router Solicitation 包
    let mut icmpv6_rs = MutableRouterSolicitPacket::new(&mut icmpv6_buf).unwrap();

    // 设置 ICMPv6 字段
    icmpv6_rs.set_icmpv6_code(Icmpv6Code(0));
    icmpv6_rs.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    icmpv6_rs.set_reserved(0);

    // 构建可变 IPv6 头部
    let mut ip_header = MutableIpv6Packet::new(&mut ip_buf).unwrap();
    let local_addr_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    // 设置 IPv6 字段
    ip_header.set_destination(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002));
    ip_header.set_source(local_addr_v6);
    ip_header.set_version(6);
    ip_header.set_traffic_class(1);
    ip_header.set_flow_label(1);
    ip_header.set_hop_limit(0xff);
    ip_header.set_next_header(IpNextHeaderProtocols::Icmpv6);

    // 计算校验和
    let icmpv6_packet = Icmpv6Packet::new(icmpv6_rs.packet()).unwrap();
    let checksum = checksum(
        &icmpv6_packet,
        &local_addr_v6,
        &Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002),
    );

    // 设置 ICMPv6 校验和
    icmpv6_rs.set_checksum(checksum);

    // 设置 IPv6 载荷长度和载荷
    ip_header.set_payload_length(icmpv6_rs.packet().len().try_into().unwrap());
    ip_header.set_payload(icmpv6_rs.packet_mut());

    // 克隆并返回数据包向量
    ip_header.packet().clone().to_vec()
}
