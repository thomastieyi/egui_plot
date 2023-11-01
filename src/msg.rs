
use serde_json::{self, Value};

use crate::pdu_helper::pdu_helper::PduSessionPlainMsg;
#[derive(PartialEq, Eq, Hash,Debug)]
pub enum IttiTrxTag {
    PduSessionMgmt,
    NasDecoer,
    Listener,
    GtpUdp
}

#[derive(Debug,Clone)]
pub enum IttiMsg  {

    //PduSessionMgmt Msg
    PduSessionMgmtRecvPduSessionPlainMsg(PduSessionPlainMsg),
    // PduSessionMgmtModifiyPduSession(PduSessionPlainMsg),
    // PduSessionMgmtDestoryPduSession(PduSessionPlainMsg),
    PduSessionMgmtStopThread,

    //NAS-5GS decoder Msg
    Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu),
    Nas5GsStopThread,

    //Incoming server listener Msg
    ListenerInitAndRun,
    ListenerDestory,
    ListenerStopThread,

    //GTP-U UDP TRX Msg
    GtpUdpCfgSetup,
    GtpUdpSendToRemote(UdpGtpBuffer), 
    GtpUdpRecvFromRemoteThenToPduSessoin(UdpGtpBuffer),
    GtpUdpStopThread,

}
#[derive(Debug,Clone)]

pub struct NasDecoerSdu{
    pub sdu:Vec<u8>
}
#[derive(Debug,Clone)]

pub struct PlainNAS5GSMessage {
    pub data:Value
}

#[derive(Debug,Clone)]

pub struct UdpGtpBuffer {
    pub data:Value
}
