use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, RwLock}, thread, net::UdpSocket, collections::HashMap, time::{Duration, SystemTime, UNIX_EPOCH}, fs};

use crossbeam::{queue::{SegQueue, ArrayQueue}, channel::{Sender, Receiver}};
use log::{debug, trace};
use rustc_serialize::json::Json;

use crate::msg::{IttiMsg, IttiTrxTag};
#[derive(Debug,Clone)]
pub struct UdpThread {
    pub global_queue: Arc<SegQueue<IttiMsg>>,
    pub global_udp_tx_queue: Arc<ArrayQueue<Vec<u8>>>,
    pub global_udp_rx_queue: Arc<ArrayQueue<Vec<u8>>>,
    pub trx_ctrl: Arc<RwLock<HashMap<IttiTrxTag, (Sender<IttiMsg>, Receiver<IttiMsg>)>>>,
    pub running : Arc<AtomicBool>
}

impl UdpThread {
    // pub new()->UdpThread
    pub fn start(mut self){
        let tx = self.clone();
        let rx = self.clone();
        let triger = self.clone();
        //加载配置文件
        let cfg_data = fs::read_to_string("cfg.json").expect("无法读取文件");
        let config = Json::from_str(&cfg_data).unwrap();

        thread::spawn(move || {
            //tx
            
            let socket = UdpSocket::bind(format!("0.0.0.0:0")).expect(" Failed to bind socket");
            socket.set_nonblocking(true).unwrap();
            let addr = format!("{}:2152",config["armAddr"].as_string().unwrap()); 
            while tx.running.load(Ordering::Relaxed) {
                if tx.global_udp_tx_queue.is_empty() {

                    thread::sleep(Duration::from_micros(1));
                    

                }
                else {
                    match tx.global_udp_tx_queue.pop() {
                        Some(byte) => {
                            // println!("gtp {:?}",byte);
                            let _ = socket.send_to(&byte, &addr);
                        },
                        None => {
                            thread::sleep(Duration::from_micros(10));

                            // thread::sleep(Duration::from_nanos(10));
    
                        },
                    }
                }
                
            }
        });
        thread::spawn(move ||  {
            //rx
            let socket = UdpSocket::bind(format!("0.0.0.0:{}", 2152)).unwrap();
                // socket.set_nonblocking(true).unwrap();
                while rx.running.load(Ordering::Relaxed) {
                    let mut buf = [0; 4096];
                    match socket.recv_from(&mut buf) {
                        Ok((number_of_bytes, src_addr)) => {
                            // println!("{}", number_of_bytes);
                            let mut time_in = SystemTime::now().duration_since(UNIX_EPOCH)
                                                                .expect("Time went backwards");
                            rx.global_udp_rx_queue.force_push(buf[0..number_of_bytes].to_vec());
                            let mut time_out = SystemTime::now().duration_since(UNIX_EPOCH)
                                                                .expect("Time went backwards");
                            trace!("UDP RX To RingBuffer {:?} : Time Stemp {:?}", time_out - time_in, time_in);
                            // to pdu_id channle
                        },
                        Err(_) => {},
                    }
            }
        });
    }
    pub fn  stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
    
}

