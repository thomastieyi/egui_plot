use std::sync::Arc;
#[cfg(feature = "glow")]
use eframe::glow;
use egui::mutex::Mutex;
use egui_demo_lib::is_mobile;

use crate::tab_app::MyTabApp;
use crate::aom::AomApp;

#[derive(Clone, Copy, Debug)]
#[must_use]
enum Command {
    Nothing,
    ResetEverything,
}

/// The state that we persist (serialize).
#[derive(Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct State {
    // demo: DemoApp,
    app_test: MyTabApp,
    aom: AomApp,
    // #[cfg(feature = "http")]
    // http: crate::apps::HttpApp,
    // #[cfg(feature = "image_viewer")]
    // image_viewer: crate::apps::ImageViewer,
    // clock: FractalClockApp,
    // color_test: ColorTestApp,

    selected_anchor: Anchor,
    backend_panel: super::backend_panel::BackendPanel,
}
/// Wraps many demo/test apps into one.
pub struct WrapApp {
    state: State,

    #[cfg(any(feature = "glow", feature = "wgpu"))]

    dropped_files: Vec<egui::DroppedFile>,
}

impl WrapApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // egui_extras::install_image_loaders(&_cc.egui_ctx);
        let mut fonts = eframe::egui::FontDefinitions::default();
        // Install my own font (maybe supporting non-latin characters):
        fonts.font_data.insert("my_font".to_owned(),
        eframe::egui::FontData::from_static(include_bytes!("../SanJiZiHaiSongGBK-2.ttf"))); // .ttf and .otf supported

        // Put my font first (highest priority):
        fonts.families.get_mut(&eframe::egui::FontFamily::Proportional).unwrap()
            .insert(0, "my_font".to_owned());

        // Put my font as last fallback for monospace:
        fonts.families.get_mut(&eframe::egui::FontFamily::Monospace).unwrap()
            .push("my_font".to_owned());

            _cc.egui_ctx.set_fonts(fonts);

        #[allow(unused_mut)]
        let mut slf = Self {
            state: State::default(),

            #[cfg(any(feature = "glow", feature = "wgpu"))]

            dropped_files: Default::default(),
        };

        #[cfg(feature = "persistence")]
        if let Some(storage) = _cc.storage {
            if let Some(state) = eframe::get_value(storage, eframe::APP_KEY) {
                slf.state = state;
            }
        }

        slf
    }

    fn apps_iter_mut(&mut self) -> impl Iterator<Item = (&str, Anchor, &mut dyn eframe::App)> {
        let mut vec = vec![
            // (
            //     "✨ Demos",
            //     Anchor::Demo,
            //     &mut self.state.demo as &mut dyn eframe::App,
            // ),
            (
                "通感数据绘图",
                Anchor::AppTest,
                &mut self.state.app_test as &mut dyn eframe::App,
            ),
            (
                "验证终端AOM",
                Anchor::AomApp,
                &mut self.state.aom as &mut dyn eframe::App,
            ),
            // (
            //     "🖹 EasyMark editor",
            //     Anchor::EasyMarkEditor,
            //     &mut self.state.easy_mark_editor as &mut dyn eframe::App,
            // ),
            // #[cfg(feature = "http")]
            // (
            //     "⬇ HTTP",
            //     Anchor::Http,
            //     &mut self.state.http as &mut dyn eframe::App,
            // ),
            // (
            //     "🕑 Fractal Clock",
            //     Anchor::Clock,
            //     &mut self.state.clock as &mut dyn eframe::App,
            // ),
            // #[cfg(feature = "image_viewer")]
            // (
            //     "🖼 Image Viewer",
            //     Anchor::ImageViewer,
            //     &mut self.state.image_viewer as &mut dyn eframe::App,
            // ),
        ];

        // #[cfg(any(feature = "glow", feature = "wgpu"))]
        // if let Some(custom3d) = &mut self.custom3d {
        //     vec.push((
        //         "🔺 3D painting",
        //         Anchor::Custom3d,
        //         custom3d as &mut dyn eframe::App,
        //     ));
        // }

        // vec.push((
        //     "🎨 Color test",
        //     Anchor::Colors,
        //     &mut self.state.color_test as &mut dyn eframe::App,
        // ));

        vec.into_iter()
    }
}

impl eframe::App for WrapApp {
    #[cfg(feature = "persistence")]
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.state);
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        #[cfg(target_arch = "wasm32")]
        if let Some(anchor) = frame.info().web_info.location.hash.strip_prefix('#') {
            let anchor = Anchor::all().into_iter().find(|x| x.to_string() == anchor);
            if let Some(v) = anchor {
                self.state.selected_anchor = v;
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::F11)) {
            frame.set_fullscreen(!frame.info().window_info.fullscreen);
        }

        let mut cmd = Command::Nothing;
        egui::TopBottomPanel::top("wrap_app_top_bar").show(ctx, |ui| {
            egui::trace!(ui);
            ui.horizontal_wrapped(|ui| {
                ui.visuals_mut().button_frame = false;
                self.bar_contents(ui, frame, &mut cmd);
            });
        });

        self.state.backend_panel.update(ctx, frame);

        if !is_mobile(ctx) {
            cmd = self.backend_panel(ctx, frame);
        }

        self.show_selected_app(ctx, frame);

        self.state.backend_panel.end_of_frame(ctx);

        self.ui_file_drag_and_drop(ctx);

        // On web, the browser controls `pixels_per_point`.
        if !frame.is_web() {
            egui::gui_zoom::zoom_with_keyboard_shortcuts(ctx, frame.info().native_pixels_per_point);
        }

        self.run_cmd(ctx, cmd);
    }

    #[cfg(feature = "glow")]
    fn on_exit(&mut self, gl: Option<&glow::Context>) {
        // if let Some(custom3d) = &mut self.custom3d {
        //     custom3d.on_exit(gl);
        // }
    }

    #[cfg(target_arch = "wasm32")]
    fn as_any_mut(&mut self) -> Option<&mut dyn Any> {
        Some(&mut *self)
    }
}

impl WrapApp {
    fn backend_panel(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) -> Command {
        // The backend-panel can be toggled on/off.
        // We show a little animation when the user switches it.
        let is_open =
            self.state.backend_panel.open || ctx.memory(|mem| mem.everything_is_visible());

        let mut cmd = Command::Nothing;

        egui::SidePanel::left("backend_panel")
            .resizable(false)
            .show_animated(ctx, is_open, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("控制台");
                });

                ui.separator();
                self.backend_panel_contents(ui, frame, &mut cmd);
            });

        cmd
    }

    fn run_cmd(&mut self, ctx: &egui::Context, cmd: Command) {
        match cmd {
            Command::Nothing => {}
            Command::ResetEverything => {
                self.state = Default::default();
                ctx.memory_mut(|mem| *mem = Default::default());
            }
        }
    }

    fn backend_panel_contents(
        &mut self,
        ui: &mut egui::Ui,
        frame: &mut eframe::Frame,
        cmd: &mut Command,
    ) {
        self.state.backend_panel.ui(ui, frame);

        ui.separator();

        ui.horizontal(|ui| {
            if ui
                .button("Reset egui")
                .on_hover_text("Forget scroll, positions, sizes etc")
                .clicked()
            {
                ui.ctx().memory_mut(|mem| *mem = Default::default());
                ui.close_menu();
            }

            if ui.button("Reset everything").clicked() {
                *cmd = Command::ResetEverything;
                ui.close_menu();
            }
        });
    }

    fn show_selected_app(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let selected_anchor = self.state.selected_anchor;
        for (_name, anchor, app) in self.apps_iter_mut() {
            if anchor == selected_anchor || ctx.memory(|mem| mem.everything_is_visible()) {
                app.update(ctx, frame);
            }
        }
    }

    fn bar_contents(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame, cmd: &mut Command) {
        egui::widgets::global_dark_light_mode_switch(ui);

        

        ui.separator();

        let mut selected_anchor = self.state.selected_anchor;
        for (name, anchor, _app) in self.apps_iter_mut() {
            if ui
                .selectable_label(selected_anchor == anchor, name)
                .clicked()
            {
                selected_anchor = anchor;
                if frame.is_web() {
                    ui.output_mut(|o| o.open_url(format!("#{anchor}")));
                }
            }
        }
        self.state.selected_anchor = selected_anchor;

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {


            egui::warn_if_debug_build(ui);
            ui.separator();

            if is_mobile(ui.ctx()) {
                ui.menu_button("💻 Backend", |ui| {
                    ui.set_style(ui.ctx().style()); // ignore the "menu" style set by `menu_button`.
                    self.backend_panel_contents(ui, frame, cmd);
                });
            } else {
                ui.toggle_value(&mut self.state.backend_panel.open, "控制台");
            }
        });
    }

    fn ui_file_drag_and_drop(&mut self, ctx: &egui::Context) {
        use egui::*;
        use std::fmt::Write as _;

        // Preview hovering files:
        if !ctx.input(|i| i.raw.hovered_files.is_empty()) {
            let text = ctx.input(|i| {
                let mut text = "Dropping files:\n".to_owned();
                for file in &i.raw.hovered_files {
                    if let Some(path) = &file.path {
                        write!(text, "\n{}", path.display()).ok();
                    } else if !file.mime.is_empty() {
                        write!(text, "\n{}", file.mime).ok();
                    } else {
                        text += "\n???";
                    }
                }
                text
            });

            let painter =
                ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("file_drop_target")));

            let screen_rect = ctx.screen_rect();
            painter.rect_filled(screen_rect, 0.0, Color32::from_black_alpha(192));
            painter.text(
                screen_rect.center(),
                Align2::CENTER_CENTER,
                text,
                TextStyle::Heading.resolve(&ctx.style()),
                Color32::WHITE,
            );
        }

        // Collect dropped files:
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                self.dropped_files = i.raw.dropped_files.clone();
            }
        });

        // Show dropped files (if any):
        // if !self.dropped_files.is_empty() {
        //     let mut open = true;
        //     egui::Window::new("Dropped files")
        //         .open(&mut open)
        //         .show(ctx, |ui| {
        //             for file in &self.dropped_files {
        //                 let mut info = if let Some(path) = &file.path {
        //                     path.display().to_string()
        //                 } else if !file.name.is_empty() {
        //                     file.name.clone()
        //                 } else {
        //                     "???".to_owned()
        //                 };

        //                 let mut additional_info = vec![];
        //                 // if !file.mime.is_empty() {
        //                 //     additional_info.push(format!("type: {}", file.mime));
        //                 // }
        //                 if let Some(bytes) = &file.bytes {
        //                     additional_info.push(format!("{} bytes", bytes.len()));
        //                 }
        //                 if !additional_info.is_empty() {
        //                     info += &format!(" ({})", additional_info.join(", "));
        //                 }

        //                 ui.label(info);
        //             }
        //         });
        //     if !open {
        //         self.dropped_files.clear();
        //     }
        // }
    }
}



#[derive(Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DemoApp {
    demo_windows: egui_demo_lib::DemoWindows,
}

impl eframe::App for DemoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.demo_windows.ui(ctx);
    }
}




#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
enum Anchor {
    // Demo,
    AppTest,
    AomApp,
    // #[cfg(feature = "http")]
    // Http,
    // #[cfg(feature = "image_viewer")]
    // ImageViewer,
    // Clock,
    // #[cfg(any(feature = "glow", feature = "wgpu"))]
    // Custom3d,
    // Colors,
}

impl Anchor {
    #[cfg(target_arch = "wasm32")]
    fn all() -> Vec<Self> {
        vec![
            Anchor::Demo,
            Anchor::EasyMarkEditor,
            #[cfg(feature = "http")]
            Anchor::Http,
            Anchor::Clock,
            #[cfg(any(feature = "glow", feature = "wgpu"))]
            Anchor::Custom3d,
            Anchor::Colors,
        ]
    }
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Anchor> for egui::WidgetText {
    fn from(value: Anchor) -> Self {
        Self::RichText(egui::RichText::new(value.to_string()))
    }
}

impl Default for Anchor {
    fn default() -> Self {
        Self::AppTest
    }
}

// ----------------------------------------------------------------------------
fn clock_button(ui: &mut egui::Ui, seconds_since_midnight: f64) -> egui::Response {
    let time = seconds_since_midnight;
    let time = format!(
        "{:02}:{:02}:{:02}.{:02}",
        (time % (24.0 * 60.0 * 60.0) / 3600.0).floor(),
        (time % (60.0 * 60.0) / 60.0).floor(),
        (time % 60.0).floor(),
        (time % 1.0 * 100.0).floor()
    );

    ui.button(egui::RichText::new(time).monospace())
}
