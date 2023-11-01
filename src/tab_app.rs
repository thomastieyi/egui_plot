use std::{f64::*, thread, sync::atomic::{AtomicBool, Ordering}, net::UdpSocket, time::{SystemTime, UNIX_EPOCH}, mem::size_of};
use egui::{mutex::Mutex, plot::{Plot, Legend, PlotPoints, Line, Corner, CoordinatesFormatter, LineStyle}, epaint::image, ColorImage, Color32, NumExt};
use egui_glow::glow;
use rand::Rng;
use std::sync::{Arc, RwLock};
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
pub(crate) struct MyTabApp {
    time: f64,
    line_style: LineStyle,
    plot_point : Arc<RwLock<PlotStruct>>,
    pub running : Arc<AtomicBool>,
}
impl Default for MyTabApp {
    fn default() -> Self {
        Self {
            time: 0.0,
            line_style: LineStyle::Solid,
            plot_point: PlotStruct::default(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl MyTabApp {

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

    fn sin(&self) -> Line {
        let time = self.time;
        let mut rng = rand::thread_rng();
        let random_number = rng.gen_range(1..101);
        Line::new(PlotPoints::from_explicit_callback(
            
            move |x| 0.5 * (2.0 * x).sin() * random_number as f64,
            ..,
            512,
        ))
        .color(Color32::from_rgb(200, 100, 100))
        .style(self.line_style)
        .name("wave")
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

impl eframe::App for MyTabApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {

        //
        if !self.running.load(Ordering::Relaxed){
            self.running.store(true, Ordering::Relaxed);
            self.recv();
        }
        //

        let mut plot_rect = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            // these are just some dummy variables for the example,
            // such that the plot is not at position (0,0)
            let height = 400.0;
            let border_x = 0.0;
            let border_y = 0.0;
            let width = 900.0;
            ui.vertical_centered_justified(|ui| {
                ui.heading("ISAC Plot 1");
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
                self.time += ui.input(|i| i.unstable_dt).at_most(1.0 / 30.0) as f64;
                let mut my_plot = Plot::new("ISAC Plot 1")
                    .height(height - 80.0)
                    // .width(width)
                    .allow_boxed_zoom(false)
                    .allow_drag(false)
                    .allow_scroll(false)
                    // .center_x_axis(true)
                    
                    .legend(Legend::default())
                    .show_axes([true;2])
                    ;
                // my_plot = my_plot.view_aspect(1.0);
                // my_plot = my_plot.data_aspect(1.0);
                // my_plot = my_plot.coordinates_formatter(Corner::LeftBottom, CoordinatesFormatter::default());
                // let's create a dummy line in the plot
                let graph: Vec<[f64; 2]> = vec![[0.0, 1.0], [2.0, 3.0], [3.0, 2.0]];
                let inner = my_plot.show(ui, |plot_ui| {
                    plot_ui.line(self.isac_plot_1());
                    plot_ui.line(self.isac_plot_2());
                });
                // Remember the position of the plot
                plot_rect = Some(inner.response.rect);
            });
        });

    }
    
    fn post_rendering(&mut self, _screen_size_px: [u32; 2], frame: &eframe::Frame) {
        // this is inspired by the Egui screenshot example
        if let Some(screenshot) = frame.screenshot() {
        }
    }
}

