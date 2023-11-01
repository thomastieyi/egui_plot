use super::{pdu_accept::{PduSessionEstablishmentAcceptMsg, PduAddressType}, pdu_modify::PduSessioModifyMsg};

pub type ExtendedProtocolDiscriminator = u8;
pub type PDUSessionIdentity = u8;
pub type ProcedureTransactionIdentity = u8;
#[derive(Debug, PartialEq,Clone)]
pub enum SessionMessageType {
    Unknown,
    EstablishmentRequest,
    EstablishmentAccept,
    EstablishmentReject,
    AuthenticationCommand,
    AuthenticationComplete,
    AuthenticationResult,
    ModificationRequest,
    ModificationReject,
    ModificationCommand,
    ModificationComplete,
    ModificationCommandReject,
    ReleaseRequest,
    ReleaseReject,
    ReleaseCommand,
    ReleaseComplete,
}
impl SessionMessageType {
    pub(crate) fn from_u8(val: u8) -> SessionMessageType {
        match val {
            0b00000001 => SessionMessageType::Unknown,
            0b11000001 => SessionMessageType::EstablishmentRequest,
            0b11000010 => SessionMessageType::EstablishmentAccept,
            0b11000011 => SessionMessageType::EstablishmentReject,

            0b11000101 => SessionMessageType::AuthenticationCommand,
            0b11000110 => SessionMessageType::AuthenticationComplete,
            0b11000111 => SessionMessageType::AuthenticationResult,

            0b11001001 => SessionMessageType::ModificationRequest,
            0b11001010 => SessionMessageType::ModificationReject,
            0b11001011 => SessionMessageType::ModificationCommand,
            0b11001100 => SessionMessageType::ModificationComplete,
            0b11001101 => SessionMessageType::ModificationCommandReject,

            0b11010001 => SessionMessageType::ReleaseRequest,
            0b11010010 => SessionMessageType::ReleaseReject,
            0b11010011 => SessionMessageType::ReleaseCommand,
            0b11010100 => SessionMessageType::ReleaseComplete,

            _ => SessionMessageType::Unknown,
        }
    }
    pub fn default() -> SessionMessageType {
        SessionMessageType::EstablishmentAccept
    }
}
#[repr(C)]
#[derive(Debug, Clone)]
pub enum PduSessionPlainMsg  {
    EstablishmentAccept(PduSessionEstablishmentAcceptMsg),
    ModificationCommand(PduSessioModifyMsg),
    DeletePduSession(PDUSessionIdentity),
    DeleteAllPduSessions
} 
#[derive(Debug, Clone)]
pub struct PduSessionPlainMsgHdr {
    pub extendedprotocoldiscriminator: ExtendedProtocolDiscriminator,
    pub pdusessionidentity: PDUSessionIdentity,
    pub proceduretransactionidentity: ProcedureTransactionIdentity,
    pub messagetype: SessionMessageType,
}
impl  PduSessionPlainMsgHdr {
    pub fn decode_vec(data: Vec<u8>) -> SessionMessageType {
        let mut index: usize = 0;
        let mut res: PduSessionEstablishmentAcceptMsg = PduSessionEstablishmentAcceptMsg::new();
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
        res.messagetype = SessionMessageType::from_u8(data[index]);
        index += 1;
        res.messagetype
    }
}
