use std::{fs::File, time::{SystemTime, UNIX_EPOCH}, io::{self, BufRead}};
use pcap_file::{pcap, TsResolution, Endianness};
use serde_json;
pub fn nas_5gs_decoder_to_json(nas_hex: Vec<u8>) -> Result<serde_json::Value, serde_json::Error> {
    let prefix: Vec<u8>  = vec![0x00,0x0c,0x00,0x07,0x6e,0x61,0x73,0x2d,0x35,0x67,0x73,0x00,0x00,0x00,0x00];
    let mut result = prefix.clone();
    result.extend(nas_hex);
    let header = pcap_file::pcap::PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: pcap_file::DataLink::WIRESHARK_UPPER_PDU,
        ts_resolution: TsResolution::MicroSecond,
        endianness: Endianness::native(),
    };
    let file = File::create("a.pcap").unwrap();
    let mut writer = pcap_file::pcap::PcapWriter::with_header(file,header ).unwrap();
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    writer
                        .write_packet(
                            &pcap::PcapPacket { timestamp: now, orig_len: result.len() as u32, data: std::borrow::Cow::Borrowed(&result) }
                        )
                        .unwrap();
    let mut tshark_process = std::process::Command::new("tshark")
        .args(["-V", "-T", "json", "-r", "a.pcap"])
        .stdout(std::process::Stdio::piped())
        .spawn().unwrap();
    let stdout = tshark_process.stdout.as_mut().unwrap();
    let output = io::BufReader::new(stdout).lines();
    let output_str = output.collect::<Result<Vec<_>, _>>().unwrap()
    .join("\n");
    serde_json::from_str(&output_str)
    // Ok(res)
}

pub fn nas_5gs_decoder_to_text(nas_hex: Vec<u8>) -> Result<String, ()> {
    let prefix: Vec<u8>  = vec![0x00,0x0c,0x00,0x07,0x6e,0x61,0x73,0x2d,0x35,0x67,0x73,0x00,0x00,0x00,0x00];
    let mut result = prefix.clone();
    result.extend(nas_hex);
    let header = pcap_file::pcap::PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: pcap_file::DataLink::WIRESHARK_UPPER_PDU,
        ts_resolution: TsResolution::MicroSecond,
        endianness: Endianness::native(),
    };
    let file = File::create("a.pcap").unwrap();
    let mut writer = pcap_file::pcap::PcapWriter::with_header(file,header ).unwrap();
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
    writer
                        .write_packet(
                            &pcap::PcapPacket { timestamp: now, orig_len: result.len() as u32, data: std::borrow::Cow::Borrowed(&result) }
                        )
                        .unwrap();
    let mut tshark_process = std::process::Command::new("tshark")
        .args(["-V", "-r", "a.pcap"])
        .stdout(std::process::Stdio::piped())
        .spawn().unwrap();
    let stdout = tshark_process.stdout.as_mut().unwrap();
    let output = io::BufReader::new(stdout).lines();
    let output_str = output.collect::<Result<Vec<_>, _>>().unwrap()
    .join("\n");
    // serde_json::from_str(&output_str)
    Ok(output_str.to_string())
    // Ok(res)
}


// pub fn nas_5gs_decode_to_plain_msg(nas_hex: Vec<u8>) -> 