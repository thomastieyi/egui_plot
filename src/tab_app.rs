use std::sync::Arc;

use egui::{mutex::Mutex, plot::{Plot, Legend, PlotPoints, Line}, epaint::image, ColorImage};
use egui_glow::glow;


#[derive(Default)]
pub(crate) struct MyTabApp {
    screenshot: Option<ColorImage>,
}

impl eframe::App for MyTabApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let mut plot_rect = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            // these are just some dummy variables for the example,
            // such that the plot is not at position (0,0)
            let height = 300.0;
            let border_x = 0.0;
            let border_y = 0.0;
            let width = 300.0;

            ui.heading("My egui Application");

            // add some whitespace in y direction
            ui.add_space(border_y);

            if ui.button("Save Plot").clicked() {
                frame.request_screenshot();
            }

            // add some whitespace in y direction
            ui.add_space(border_y);

            ui.horizontal(|ui| {
                // add some whitespace in x direction
                ui.add_space(border_x);

                let my_plot = Plot::new("My Plot")
                    .height(height)
                    .width(width)
                    .legend(Legend::default());

                // let's create a dummy line in the plot
                let graph: Vec<[f64; 2]> = vec![[0.0, 1.0], [2.0, 3.0], [3.0, 2.0]];
                let inner = my_plot.show(ui, |plot_ui| {
                    plot_ui.line(Line::new(PlotPoints::from(graph)).name("curve"));
                });
                // Remember the position of the plot
                plot_rect = Some(inner.response.rect);
            });

            // add some whitespace in y direction
            ui.add_space(border_y);
        });

        if let (Some(screenshot), Some(plot_location)) = (self.screenshot.take(), plot_rect) {
            // if let Some(mut path) = rfd::FileDialog::new().save_file() {
            //     path.set_extension("png");

            //     // for a full size application, we should put this in a different thread,
            //     // so that the GUI doesn't lag during saving

            //     let pixels_per_point = frame.info().native_pixels_per_point;
            //     let plot = screenshot.region(&plot_location, pixels_per_point);
            //     // save the plot to png
            //     image::save_buffer(
            //         &path,
            //         plot.as_raw(),
            //         plot.width() as u32,
            //         plot.height() as u32,
            //         image::ColorType::Rgba8,
            //     )
            //     .unwrap();
            // }
        }
    }

    fn post_rendering(&mut self, _screen_size_px: [u32; 2], frame: &eframe::Frame) {
        // this is inspired by the Egui screenshot example
        if let Some(screenshot) = frame.screenshot() {
            self.screenshot = Some(screenshot);
        }
    }
}
