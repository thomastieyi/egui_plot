use std::{net::UdpSocket, thread, time::Duration};

#[derive(Debug,Clone)]
pub struct CtrlMsg {

    pub msg_type : MSG_TYPE,
    pub tlv_data : TLV_DATA

}

#[derive(Debug,Clone)]
pub enum MSG_TYPE {
    ARM_CONNECTING_MSG=0x01,
    PDU_SESSION_ESTABLISHMENT_MSG=0x02,
    PDU_SESSION_MODIFY_MSG=0x03,
    PDU_SESSION_RELEASE_MSG=0x04,
    PCSCF_DNS_ASK_MSG=0x05,
    ARM_RELEASE_MSG=0xff,
    UNKNOW=0x06,
}
impl MSG_TYPE {
    pub fn from_u8(ie : u8) -> MSG_TYPE {
        match ie {
            0x01 => MSG_TYPE::ARM_CONNECTING_MSG,
            0x02 => MSG_TYPE::PDU_SESSION_ESTABLISHMENT_MSG,
            0x03 => MSG_TYPE::PDU_SESSION_MODIFY_MSG,
            0x04 => MSG_TYPE::PDU_SESSION_RELEASE_MSG,
            0x05 => MSG_TYPE::PCSCF_DNS_ASK_MSG,
            0xff => MSG_TYPE::ARM_RELEASE_MSG,
               _ => MSG_TYPE::UNKNOW
        }
    }
}

#[derive(Debug,Clone)]
pub struct  TLV_DATA {
    pub data: Vec<u8>
}

impl CtrlMsg {
    pub fn decode_from_udp_pkt(data: Vec<u8>) -> CtrlMsg{
            let mut index = 0;
            let msg_type = MSG_TYPE::from_u8(data[index]);
            index += 1;
            let length = (data[index ] as u16) << 8 | data[index + 1] as u16;
            index += 2;
            let tlv_data = TLV_DATA {
                data: data[index..index+length as usize].to_vec(),
            };
            CtrlMsg { msg_type: msg_type, tlv_data: tlv_data  }
    }

    pub fn encode_to_vec(mut self) ->Vec<u8> {
         let mut msg_tag : u8 = match self.msg_type {
            MSG_TYPE::ARM_CONNECTING_MSG => 0x01,
            MSG_TYPE::PDU_SESSION_ESTABLISHMENT_MSG => 0x02,
            MSG_TYPE::PDU_SESSION_MODIFY_MSG => 0x03,
            MSG_TYPE::PDU_SESSION_RELEASE_MSG => 0x04,
            MSG_TYPE::PCSCF_DNS_ASK_MSG => 0x05,
            MSG_TYPE::ARM_RELEASE_MSG => 0xff,
            MSG_TYPE::UNKNOW => 0x06,
        };
        let mut res = self.tlv_data.data.clone();
        let length = self.tlv_data.data.len();
        let len_high:u8 = ((length as u16) >> 8) as u8;
        let len_low:u8 = ((length as u16) & 0b0000000011111111) as u8;
        let mut hdr = vec![msg_tag,len_high,len_low];
        hdr.extend(res.iter());
        hdr
    }
}

#[test]
pub fn test_arm_send_connecting_msg_to_pc() {
    //tx
    let socket = UdpSocket::bind("0.0.0.0:0").expect(" Failed to bind socket");
    let addr = "127.0.0.1:8080"; 
    let ctl_msg_connect = CtrlMsg { msg_type: MSG_TYPE::ARM_CONNECTING_MSG, tlv_data: TLV_DATA { data: vec![] } };
    println!("{:?}",ctl_msg_connect.clone().encode_to_vec());
    let _ = socket.send_to(&ctl_msg_connect.encode_to_vec(), addr);

}

#[test]
pub fn test_arm_send_establishment_msg_to_pc() {
    //tx
    let socket = UdpSocket::bind("0.0.0.0:0").expect(" Failed to bind socket");
    let addr = "127.0.0.1:8080"; 
    let ctl_msg_establishment = CtrlMsg { msg_type: MSG_TYPE::PDU_SESSION_ESTABLISHMENT_MSG, tlv_data: TLV_DATA { data: vec![
        0x2e, 0x01, 0x01, 0xc2, 0x12, 0x00, 0x09, 0x01, 0x00, 0x06, 0x31, 0x20, 0x01, 0x01,
        0xff, 0x01, 0x06, 0x01, 0x27, 0x10, 0x01, 0x27, 0x10, 0x59, 0x33, 0x29, 0x09, 0x02,
        0x17, 0x7c, 0x23, 0x76, 0xb8, 0x11, 0xe4, 0xbe, 0x22, 0x04, 0x01, 0x00, 0x00, 0x00,
        0x79, 0x00, 0x06, 0x01, 0x20, 0x41, 0x01, 0x01, 0x05, 0x7b, 0x00, 0x27, 0x80, 0x00,
        0x01, 0x10, 0x24, 0x0e, 0x00, 0x66, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x24, 0x00, 0x01, 0x10, 0x24, 0x0e, 0x00, 0x66, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x25, 0x04, 0x03, 0x69, 0x6d,
        0x73,
    ] } };
    let _ = socket.send_to(&ctl_msg_establishment.encode_to_vec(), addr);

}

#[test]
pub fn test_arm_send_modify_add_drb_msg_to_pc() {
    //tx
    let socket = UdpSocket::bind("0.0.0.0:0").expect(" Failed to bind socket");
    let addr = "127.0.0.1:8080"; 
    let ctl_msg_modify = CtrlMsg { msg_type: MSG_TYPE::PDU_SESSION_MODIFY_MSG, tlv_data: TLV_DATA { data: vec![
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
        0x04, 0x03, 0x01, 0x00, 0x2c, 0x05, 0x03, 0x01, 0x00, 0x2c,] } };
    let _ = socket.send_to(&ctl_msg_modify.encode_to_vec(), addr);

}

#[test]
pub fn test_arm_send_modify_del_drb_msg_to_pc() {
    //tx
    let socket = UdpSocket::bind("0.0.0.0:0").expect(" Failed to bind socket");
    let addr = "127.0.0.1:8080"; 
    let ctl_msg_modify = CtrlMsg { msg_type: MSG_TYPE::PDU_SESSION_MODIFY_MSG, tlv_data: TLV_DATA { data: vec![
        0x2e,0x01,0x00,0xcb,0x7a,0x00,0x08,0x02,0x00,0x01,0x40,0x03,0x00,0x01,0x40,0x79,0x00,0x03,
        0x02,0x40,0x00] } };
    let _ = socket.send_to(&ctl_msg_modify.encode_to_vec(), addr);

}
#[test]
pub fn test_arm_send_release_to_pc() {
    //tx
    let socket = UdpSocket::bind("0.0.0.0:0").expect(" Failed to bind socket");
    let addr = "127.0.0.1:8080"; 
    let ctl_msg_modify = CtrlMsg { msg_type: MSG_TYPE::ARM_RELEASE_MSG, tlv_data: TLV_DATA { data: vec![] } };
    println!("{:?}",ctl_msg_modify.clone().encode_to_vec());
    let _ = socket.send_to(&ctl_msg_modify.encode_to_vec(), addr);

}

#[test]
pub fn test_all() {
    println!("Begin TEST");
    thread::sleep(Duration::from_secs(1));
    println!("test_arm_send_connecting_msg_to_pc");
    test_arm_send_connecting_msg_to_pc();
    thread::sleep(Duration::from_secs(1));
    println!("test_arm_send_establishment_msg_to_pc");
    test_arm_send_establishment_msg_to_pc();
    thread::sleep(Duration::from_secs(1));
    println!("test_arm_send_modify_add_drb_msg_to_pc");
    test_arm_send_modify_add_drb_msg_to_pc();
    thread::sleep(Duration::from_secs(1));
    println!("test_arm_send_modify_del_drb_msg_to_pc");
    test_arm_send_modify_del_drb_msg_to_pc();
    thread::sleep(Duration::from_secs(1));
    println!("test_arm_send_release_to_pc");
    test_arm_send_release_to_pc();
}