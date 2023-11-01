#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
#![allow(unsafe_code)]
mod nas_decoder;
mod pdu_helper;
mod gtp_u_helper;
mod route_helper;
mod ctrl_helper;
mod msg;
mod aom;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{time, thread, fs};
use crossbeam::channel::{unbounded, Receiver ,Sender};
use crossbeam::queue::{SegQueue, ArrayQueue};
use crossbeam::scope;
use log::{info, debug};
use msg::{IttiMsg, IttiTrxTag, PlainNAS5GSMessage, NasDecoerSdu};
use nas_decoder::{nas_5gs_decoder_to_json, nas_5gs_decoder_to_text};
use pdu_helper::pdu_helper::PduSessionPlainMsgHdr;
use pdu_helper::pdu_modify::PduSessioModifyMsg;
use pdu_helper::pdu_session_mgmt::PduSessionMgmt;
use rustc_serialize::json::Json;

use crate::ctrl_helper::ctrl_helper::{CtrlMsg, MSG_TYPE};
use crate::pdu_helper::pdu_accept::PduSessionEstablishmentAcceptMsg;
use crate::pdu_helper::pdu_helper::PduSessionPlainMsg;
use crate::gtp_u_helper::gtp_u_udp::UdpThread;
mod main_frame;
mod backend_panel;
mod frame_history;
mod tab_app;
use eframe::{egui, IconData};

use egui::mutex::Mutex;
use egui_glow::glow;
use main_frame::WrapApp;

fn main() -> Result<(), eframe::Error> {
    {
        // Silence wgpu log spam (https://github.com/gfx-rs/wgpu/issues/3206)
        let mut rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
        for loud_crate in ["naga", "wgpu_core", "wgpu_hal"] {
            if !rust_log.contains(&format!("{loud_crate}=")) {
                rust_log += &format!(",{loud_crate}=warn");
            }
        }
        std::env::set_var("RUST_LOG", rust_log);
    }
    //加载配置文件
    let cfg_data = fs::read_to_string("cfg.json").expect("无法读取文件");
    let config = Json::from_str(&cfg_data).unwrap();
    let log_level = config["logLevel"].as_string().unwrap();
    std::env::set_var("RUST_LOG", log_level);
    env_logger::Builder::from_default_env().parse_env("RUST_LOG").init();
    // env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    let options = eframe::NativeOptions {
        drag_and_drop_support: true,
        icon_data: Some(
            IconData::try_from_png_bytes(&include_bytes!("../data/vivo.png")[..]).unwrap(),
        ),
        initial_window_size: Some([1280.0, 1024.0].into()),

        #[cfg(feature = "wgpu")]
        renderer: eframe::Renderer::Wgpu,

        ..Default::default()
    };
    eframe::run_native(
        "vivo 数据面",
        options,
        Box::new(|cc| Box::new(WrapApp::new(cc))),
    )
}

