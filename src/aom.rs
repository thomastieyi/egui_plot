use std::{f64::*, thread, sync::atomic::{AtomicBool, Ordering}, net::UdpSocket, time::{SystemTime, UNIX_EPOCH, Duration}, mem::size_of, collections::HashMap, fs};
use egui::{mutex::Mutex, plot::{Plot, Legend, PlotPoints, Line, Corner, CoordinatesFormatter, LineStyle}, epaint::image, ColorImage, Color32, NumExt};
use crossbeam::channel::{unbounded, Receiver ,Sender};
use crossbeam::queue::{SegQueue, ArrayQueue};
use log::{info, debug};
use rand::Rng;
use rustc_serialize::json::Json;
use std::sync::{Arc, RwLock};

use crate::{msg::{IttiMsg, IttiTrxTag, NasDecoerSdu}, gtp_u_helper::gtp_u_udp::UdpThread, pdu_helper::{pdu_session_mgmt::PduSessionMgmt, self, pdu_modify::PduSessioModifyMsg, pdu_helper::{PduSessionPlainMsg, PduSessionPlainMsgHdr}, pdu_accept::PduSessionEstablishmentAcceptMsg}, ctrl_helper::{ctrl_helper::{MSG_TYPE, CtrlMsg}, self}};
#[repr(C)]
#[derive(Clone)]
pub struct PlotStruct {
    fig1: [f32; 2050],
    fig1_size: usize,
    fig2: [f32; 2050],
    fig2_size: usize,
}
impl  PlotStruct {
    fn default() -> Arc<RwLock<PlotStruct>> {
        Arc::new(RwLock::new(PlotStruct {
                    fig1: [0.0; 2050],
                    fig1_size: 2050,
                    fig2: [0.0; 2050],
                    fig2_size: 2050,
                }))
    }
    fn from_self(mut self,plot: PlotStruct) {
        self.fig1 = plot.fig1;
        self.fig1_size = plot.fig1_size;
        self.fig2 = plot.fig2;
        self.fig2_size = plot.fig2_size;
    }
}
pub(crate) struct AomApp {
    time: f64,
    line_style: LineStyle,
    plot_point : Arc<RwLock<PlotStruct>>,
    pub running : Arc<AtomicBool>,
    global_task_queue: Arc<SegQueue<IttiMsg>> ,
    global_rx_queue: Arc<ArrayQueue<Vec<u8>>>,
    global_tx_queue: Arc<ArrayQueue<Vec<u8>>>,
    global_itti_trx_tag_list: Arc<RwLock<HashMap<IttiTrxTag, (Sender<IttiMsg>, Receiver<IttiMsg>)>>>

}
impl Default for AomApp {
    fn default() -> Self {
        Self {
            time: 0.0,
            line_style: LineStyle::Solid,
            plot_point: PlotStruct::default(),
            running: Arc::new(AtomicBool::new(false)),
            global_task_queue: Arc::new(SegQueue::<IttiMsg>::new()),
            global_rx_queue: Arc::new(ArrayQueue::<Vec<u8>>::new(3000)),
            global_tx_queue: Arc::new(ArrayQueue::<Vec<u8>>::new(3000)),
            global_itti_trx_tag_list: Arc::new(RwLock::new(HashMap::<IttiTrxTag,(Sender<IttiMsg>,Receiver<IttiMsg>)>::new())),
        }
    }
}
impl AomApp {

    fn recv(&mut self) {
        let mut running = self.running.clone();
        let mut plot_point = self.plot_point.clone();
        println!("Begin recv");
        thread::spawn(move ||{
            let socket = UdpSocket::bind(format!("0.0.0.0:{}", 12345)).unwrap();
            println!("Begin socket");
            while running.load(Ordering::Relaxed) {
                let mut buf = [0; 16416];
                match socket.recv_from(&mut buf) {
                    Ok((number_of_bytes, src_addr)) => {
                        // println!("{}", number_of_bytes);
                        let mut time_in = SystemTime::now().duration_since(UNIX_EPOCH)
                                                            .expect("Time went backwards");
                                                        {
                                                            loop {
                                                                let b = plot_point.try_write();
                                                                match b {
                                                                    Ok(mut b) => {
                                                                        let a = unsafe { std::mem::transmute::<[u8; size_of::<PlotStruct>()], PlotStruct>(buf) };
                                                                        b.fig1 = a.fig1;
                                                                        b.fig2 = a.fig2;
                                                                        b.fig1_size = a.fig1_size;
                                                                        b.fig2_size = a.fig2_size;
                                                                        drop(a);
                                                                        break;
                                                                    },
                                                                    Err(_) => {
                                                                        continue;
                                                                    },
                                                                }
                                                            }
                                                        }
                        
                        let mut time_out = SystemTime::now().duration_since(UNIX_EPOCH)
                                                            .expect("Time went backwards");
                        // to pdu_id channle
                    },
                    Err(_) => {},
                }
        }
        });
    }


    fn start_hl_driver(&mut self) {
    //加载配置文件
    let cfg_data = fs::read_to_string("cfg.json").expect("无法读取文件");
    let config = Json::from_str(&cfg_data).unwrap();
    //for PDU Session Thread
    let mut running_pdu = self.running.clone();
    let global_task_queue_pdu = self.global_task_queue.clone();
    let global_itti_trx_tag_list_pdu = self.global_itti_trx_tag_list.clone();
    let global_tx_queue_udp_thread_pdu: Arc<ArrayQueue<Vec<u8>>> = self.global_tx_queue.clone();
    let global_rx_queue_udp_thread_pdu: Arc<ArrayQueue<Vec<u8>>> = self.global_rx_queue.clone();

    //for NAS Decoder Thread
    let mut running_nas = self.running.clone();
    let global_task_queue_nas_decoder = self.global_task_queue.clone();
    let global_itti_trx_tag_list_nas_decoder = self.global_itti_trx_tag_list.clone();

    //for UDP GTP Thread
    let mut running_gtp = self.running.clone();
    let global_task_queue_udp_thread = self.global_task_queue.clone();
    let global_tx_queue_udp_thread: Arc<ArrayQueue<Vec<u8>>> = self.global_tx_queue.clone();
    let global_rx_queue_udp_thread = self.global_rx_queue.clone();
    let global_itti_trx_tag_list_udp_thread = self.global_itti_trx_tag_list.clone();

    //for ITTI Handller
    let mut running_itti = self.running.clone();
    let global_task_queue_handler = self.global_task_queue.clone();
    let global_itti_trx_tag_list_handler = self.global_itti_trx_tag_list.clone();

    //for Controller Handller
    let mut running_ctrl = self.running.clone();
    let global_task_queue_ctl = self.global_task_queue.clone();
    let global_itti_trx_tag_list_ctl = self.global_itti_trx_tag_list.clone();
            //Thread Controller
            thread::spawn(move ||{
                let socket: UdpSocket = UdpSocket::bind(format!("0.0.0.0:{}", config["pcUDPCtrlPort"].as_string().unwrap())).expect("msg");
                info!("Thread Controller Started");
                while running_ctrl.load(Ordering::Relaxed) {
                    let mut buf = [0; 4096];
                    match socket.recv_from(&mut buf) {
                        Ok((number_of_bytes, src_addr)) => {
                            let ctl_msg = CtrlMsg::decode_from_udp_pkt(buf[0..number_of_bytes].to_vec());
                            match ctl_msg.msg_type {
                                MSG_TYPE::ARM_CONNECTING_MSG => {
                                    info!("Thread Controller Recv : ARM_CONNECTING_MSG");
                                },
                                MSG_TYPE::PDU_SESSION_ESTABLISHMENT_MSG => {
                                    info!("Thread Controller Recv : PDU_SESSION_ESTABLISHMENT_MSG");
                                    let nas_sm_msg = IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu { sdu: ctl_msg.tlv_data.data });
                                    global_task_queue_ctl.push(nas_sm_msg);
                                },
                                MSG_TYPE::PDU_SESSION_MODIFY_MSG => {
                                    info!("Thread Controller Recv : PDU_SESSION_MODIFY_MSG");
                                    let nas_sm_msg = IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu { sdu: ctl_msg.tlv_data.data });
                                    global_task_queue_ctl.push(nas_sm_msg);
                                },
                                MSG_TYPE::PDU_SESSION_RELEASE_MSG => {
                                    info!("Thread Controller Recv : PDU_SESSION_RELEASE_MSG");
                                    let nas_sm_msg = IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu { sdu: ctl_msg.tlv_data.data });
                                    global_task_queue_ctl.push(nas_sm_msg);
                                },
                                ctrl_helper::ctrl_helper::MSG_TYPE::ARM_RELEASE_MSG => {
                                    info!("Thread Controller Recv : ARM_RELEASE_MSG");
                                    let pdu_del_all= IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg(PduSessionPlainMsg::DeleteAllPduSessions);
                                    global_task_queue_ctl.push(pdu_del_all);
                                },
                                ctrl_helper::ctrl_helper::MSG_TYPE::UNKNOW => {},
                                MSG_TYPE::PCSCF_DNS_ASK_MSG => {
                                    
                                },
                              
                            }
                            // rx.global_udp_rx_queue.push(buf[0..number_of_bytes].to_vec());
                            // to pdu_id channle
                        },
                        Err(_) => {
                            thread::sleep(Duration::from_nanos(10));
                        },
                    }

                }
            });
            
            //Thread for nas decoder
            thread::spawn(move ||{
                let nas_decoder_trx: (Sender<IttiMsg>, Receiver<IttiMsg>) = unbounded::<IttiMsg>();
                // global_itti_trx_tag_list_pdu.insert(IttiTrxTag::NasDecoer, nas_decoder_trx.clone()); // 插入
                {
                    loop {
                        let bb = global_itti_trx_tag_list_pdu.try_write();
                        match bb {
                            Ok(mut b) => {
                                b.insert(IttiTrxTag::NasDecoer, nas_decoder_trx.clone()); 
                                info!("Thread NasDecoer Started");

                                // global_itti_trx_tag_list_pdu.
                                break;
                            },
                            Err(_) => {
                                continue;
                            },
                        }
                    }
                }
                while running_nas.load(Ordering::Relaxed) {
                    match  nas_decoder_trx.1.recv() {
                        Ok(msg) => {
                            match msg {
                                IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(data_to_decode) => {
                                    match PduSessionPlainMsgHdr::decode_vec(data_to_decode.sdu.clone()) {
                                        pdu_helper::pdu_helper::SessionMessageType::Unknown => {},
                                        pdu_helper::pdu_helper::SessionMessageType::EstablishmentRequest => {},
                                        pdu_helper::pdu_helper::SessionMessageType::EstablishmentAccept => {
                                            if let Ok(plain_nas5_gsmessage) = PduSessionEstablishmentAcceptMsg::tlv_decode_pdu_session_establishment_accept(data_to_decode.sdu.clone()) {
                                                // println!("{:#?}", plain_nas5_gsmessage);
                                                global_task_queue_nas_decoder.push(IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg
                                                                    (PduSessionPlainMsg::EstablishmentAccept(plain_nas5_gsmessage)))
                                                // let bb = global_itti_trx_tag_list_pdu.try_read().unwrap();
                                                // if bb.contains_key(&IttiTrxTag::PduSessionMgmt) {
                                                //     match  bb.get(&IttiTrxTag::PduSessionMgmt){
                                                //         Some(pdu_trx) =>{
                                                //             let _ = pdu_trx.0.send(IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg
                                                //                 (PduSessionPlainMsg::EstablishmentAccept(
                                                //                     PduSessionEstablishmentAcceptMsg::tlv_decode_pdu_session_establishment_accept(data_to_decode.sdu.clone()).unwrap())));
                                                //         },
                                                //         None => {
                        
                                                //         },
                                                //     } 
                                                //     {} 
                                                // }
                                            }
                                        },
                                        pdu_helper::pdu_helper::SessionMessageType::EstablishmentReject => {},
                                        pdu_helper::pdu_helper::SessionMessageType::AuthenticationCommand => {},
                                        pdu_helper::pdu_helper::SessionMessageType::AuthenticationComplete => {},
                                        pdu_helper::pdu_helper::SessionMessageType::AuthenticationResult => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ModificationRequest => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ModificationReject => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ModificationCommand => {
                                            if let Ok(plain_nas5_gsmessage) = PduSessioModifyMsg::tlv_decode_pdu_session_modify_msg(data_to_decode.sdu.clone()) {
                                                // println!("{:#?}", plain_nas5_gsmessage);
                                                global_task_queue_nas_decoder.push(IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg
                                                                    (PduSessionPlainMsg::ModificationCommand(plain_nas5_gsmessage)))
                                                // let bb = global_itti_trx_tag_list_pdu.try_read().unwrap();
                                                // if bb.contains_key(&IttiTrxTag::PduSessionMgmt) {
                                                //     match  bb.get(&IttiTrxTag::PduSessionMgmt){
                                                //         Some(pdu_trx) =>{
                                                //             let _ = pdu_trx.0.send(IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg
                                                //                 (PduSessionPlainMsg::EstablishmentAccept(
                                                //                     PduSessionEstablishmentAcceptMsg::tlv_decode_pdu_session_establishment_accept(data_to_decode.sdu.clone()).unwrap())));
                                                //         },
                                                //         None => {
                        
                                                //         },
                                                //     } 
                                                //     {} 
                                                // }
                                            }
                                        },
                                        pdu_helper::pdu_helper::SessionMessageType::ModificationComplete => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ModificationCommandReject => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ReleaseRequest => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ReleaseReject => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ReleaseCommand => {},
                                        pdu_helper::pdu_helper::SessionMessageType::ReleaseComplete => {},
                                    }
                                    
                                },
                                IttiMsg::Nas5GsStopThread => {
                                    break;
                                },
                                _ => {},
                            }
                        },
                        Err(_) => {                            
                        },
                    }
                    
                }
            });
            

            //Thread pduSessionMgmt
            thread::spawn(move ||{
                let pdu_session_mgmt = PduSessionMgmt::default(global_task_queue_pdu,
                                                                                global_tx_queue_udp_thread_pdu,
                                                                                global_rx_queue_udp_thread_pdu);
                let pdu_trx = unbounded::<IttiMsg>();
                
                {
                loop {
                    let b = global_itti_trx_tag_list_nas_decoder.try_write();
                    match b {
                        Ok(mut b) => {
                            b.insert(IttiTrxTag::PduSessionMgmt, pdu_trx.clone());
                            break;
                        },
                        Err(_) => {
                            continue;
                        },
                    }
                }
            }
            info!("Thread pduSessionMgmt start");
                pdu_session_mgmt.init_pdu_session_mgmt_task(pdu_trx.clone());
            });


            //Thread GtpUdp
            thread::spawn(move ||{
                let gtp_udp_trx = unbounded::<IttiMsg>();
                {
                    loop {
                        let b = global_itti_trx_tag_list_udp_thread.try_write();
                        match b {
                            Ok(mut b) => {
                                b.insert(IttiTrxTag::GtpUdp, gtp_udp_trx.clone());
                                info!("Thread GtpUdp Started");
                                break;
                            },
                            Err(_) => {
                                continue;
                            },
                        }
                    }
                }

                let gtp_udp_thread = UdpThread { global_queue: global_task_queue_udp_thread, 
                                                            global_udp_tx_queue: global_tx_queue_udp_thread,
                                                            global_udp_rx_queue: global_rx_queue_udp_thread, 
                                                            trx_ctrl: global_itti_trx_tag_list_udp_thread, 
                                                            running: Arc::new(AtomicBool::new(true)) };
                let pdu_trx = unbounded::<IttiMsg>();
                gtp_udp_thread.start();
            });


            //Thread Itti Task Queue
            thread::spawn(move ||{
                info!("Thread Itti Task Queue Started");

                while running_itti.load(Ordering::Relaxed) {
                match  global_task_queue_handler.pop() {
                    Some(msg) => {
                        debug!("Thread Itti Task Queue: Recv task msg");
                        match msg{
                            IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg(plain_nas5_gsmessage)
                                  => {
                                    debug!("       TASK : PduSessionMgmtRecvPduSessionPlainMsg");

                                        loop{
                                            let global_itti_trx_tag_list_handler = global_itti_trx_tag_list_handler.try_read();
                                            match global_itti_trx_tag_list_handler {
                                                Ok(g) => {
                                                    if g.contains_key(&IttiTrxTag::PduSessionMgmt) {
                                                        let pdu_trx =  g.get(&IttiTrxTag::PduSessionMgmt);
                                                        match pdu_trx {
                                                            Some(pdu_trx) => {
                                                                let _ = pdu_trx.0.send(IttiMsg::PduSessionMgmtRecvPduSessionPlainMsg(plain_nas5_gsmessage.clone()));
                                                            },
                                                            None => {
                                                            },
                                                        }
                                                    }
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                            
                                        }
                                        
                                    },
                            IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(nas_decoer_sdu) =>{
                                debug!("       TASK : Nas5GsDecodePduAndSend2PduMgmt");

                                        loop{
                                            let global_itti_trx_tag_list_handler = global_itti_trx_tag_list_handler.try_read();
                                            match global_itti_trx_tag_list_handler {
                                                Ok(g) => {
                                                    if g.contains_key(&IttiTrxTag::NasDecoer) {
                                                        let pdu_trx =  g.get(&IttiTrxTag::NasDecoer);
                                                        match pdu_trx {
                                                            Some(pdu_trx) => {
                                                                let _ = pdu_trx.0.send(IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(nas_decoer_sdu.clone()));
                                                            },
                                                            None => {
                                                            },
                                                        }
                                                    }
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                            
                                        }
                            }
                            _ => {debug!("{:#?}", msg);},
                        }
                    },
                    None => {
                            thread::sleep(Duration::from_micros(10));

                        // println!("{:#?}", "msg");
                    },
                }
            }
        });


    }


    fn isac_plot_1(&self) -> Line {
        let time = self.time;
        let mut rng = rand::thread_rng();
        let mut plot_point = self.plot_point.clone();
        let mut fig1: [f32; 2050];
        {
            loop {
                let b = plot_point.try_read();
                match b {
                    Ok(mut b) => {
                        fig1 = b.fig1;
                        break;
                    },
                    Err(_) => {
                        continue;
                    },
                }
            }
        }
        let fig1_size = 2050;

        for i in 0..fig1_size {
            fig1[i] = fig1[i] + 1.0;
        }

        Line::new(PlotPoints::from_ys_f32(
            &fig1
        ))
        .color(Color32::from_rgb(200, 100, 100))
        .style(self.line_style)
        .name("plot1")
    }
    fn isac_plot_2(&self) -> Line {
        let time = self.time;
        let mut rng = rand::thread_rng();
        let mut plot_point = self.plot_point.clone();
        let mut fig2: [f32; 2050];
        {
            loop {
                let b = plot_point.try_read();
                match b {
                    Ok(mut b) => {
                        fig2 = b.fig2;
                        break;
                    },
                    Err(_) => {
                        continue;
                    },
                }
            }
        }
        let fig2_size = 2050;

        
        for i in 0..fig2_size {
            fig2[i] = fig2[i] - 1.0;
        }
        Line::new(PlotPoints::from_ys_f32(
            &fig2
        ))
        .color(Color32::from_rgb(100, 150, 250))
        .style(self.line_style)
        .name("plot2")
    }
}

impl eframe::App for AomApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {

        //
        if !self.running.load(Ordering::Relaxed){
            self.running.store(true, Ordering::Relaxed);
            // self.recv();
            self.start_hl_driver();
        }
        //

        // let mut plot_rect = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            // these are just some dummy variables for the example,
            // such that the plot is not at position (0,0)
            let height = 400.0;
            let border_x = 0.0;
            let border_y = 0.0;
            let width = 900.0;
            ui.vertical_centered(|ui| {
                ui.label("Welcome to the widget gallery!");
            });

            // add some whitespace in y direction
            ui.add_space(border_y);

            // if ui.button("Save Plot").clicked() {
            //     frame.request_screenshot();
            // }

            // add some whitespace in y direction
            ui.add_space(border_y);
            // println!("{:?}", ui.available_height());
            let height = ui.available_height();
            ui.horizontal(|ui| {
                // add some whitespace in x direction
                ui.add_space(border_x);
                
                
                // ui.allocate_space((ui.available_width(), 300.0).into());
                ui.ctx().request_repaint();
                
            });
        });

    }
    
    fn post_rendering(&mut self, _screen_size_px: [u32; 2], frame: &eframe::Frame) {
        // this is inspired by the Egui screenshot example
        if let Some(screenshot) = frame.screenshot() {
        }
    }
}

