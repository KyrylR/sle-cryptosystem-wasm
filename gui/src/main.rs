mod scenes;
mod state;
mod widgets;

use state::State;

use std::time::Instant;

use crate::scenes::{MainContentState, RightSideBarState};
use crate::widgets::error_popup::ErrorPopup;
use crate::widgets::help_panel::HelpPanel;
use eframe::egui;
use eframe::egui::{CentralPanel, Color32, Frame, Margin, Vec2};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;

pub struct App {
    state: State,
    last_render: Instant,
    help_panel: HelpPanel,
    error_popup: ErrorPopup,
    main_content: MainContentState,
    right_sidebar: RightSideBarState,
    shared_params: Option<SharedParams>,
    private_key: Option<PrivateKey>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            state: State::new(),
            last_render: Instant::now(),
            help_panel: HelpPanel::new(),
            error_popup: ErrorPopup::new(),
            main_content: MainContentState::setup(),
            right_sidebar: RightSideBarState::setup(),
            shared_params: None,
            private_key: None,
        }
    }

    pub(crate) fn update(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.error_popup.update(ctx);
        
        ui.horizontal_top(|ui| {
            Frame::default()
                .outer_margin(Margin::same(50))
                .inner_margin(Margin::same(20))
                .show(ui, |ui| self.render_split(ui, ctx));
        });
    }
    
    fn render_split(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal_top(|ui| {
            let available_width = ui.available_width();
            let main_width = available_width * 0.8;
            let button_width = available_width * 0.2;

            // Main content area (80%)
            ui.allocate_ui_with_layout(
                egui::vec2(main_width, ui.available_height()),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    self.main_content.render(ui, ctx, &self.shared_params, &self.private_key);
                },
            );

            // Button area (20%)
            ui.allocate_ui_with_layout(
                egui::vec2(button_width, ui.available_height()),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    Frame::default().show(ui, |ui| {
                        if let Some((params, private_key)) = self.right_sidebar.render(ui, ctx)  {
                            self.shared_params = Some(params);
                            self.private_key = private_key;
                        } 
                    });
                },
            );
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        log::trace!(
            "Frame rendering time: {}",
            self.last_render.elapsed().as_millis()
        );

        // Redefine frame for some custom properties with light theme
        let my_frame = Frame {
            fill: Color32::from_rgb(248, 248, 248), // Light background
            shadow: eframe::epaint::Shadow::NONE,
            inner_margin: Margin::same(0), // Remove default margin since we handle it in update
            ..Default::default()
        };

        CentralPanel::default().frame(my_frame).show(ctx, |ui| {
            self.update(ui, ctx);
        });

        // Render help panel on top of other UI elements
        self.help_panel.render(ctx);

        self.last_render = Instant::now();
    }
}

fn main() -> eframe::Result {
    // Log to stderr (if you run with `RUST_LOG=debug`).
    env_logger::init();

    let window_size = Vec2::new(1400.0, 900.0);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(window_size),
        ..Default::default()
    };

    let app = App::new();
    eframe::run_native(
        "SLE Cryptosystem - Symmetric cryptosystem based on ring images",
        options,
        Box::new(move |ctx| {
            let mut visuals = egui::Visuals::light();
            visuals.override_text_color = Some(Color32::BLACK);
            visuals.panel_fill = Color32::from_rgb(248, 248, 248); // Light panel background
            visuals.window_fill = Color32::from_rgb(255, 255, 255); // White window background
            visuals.extreme_bg_color = Color32::from_rgb(240, 240, 240); // Light extreme background

            ctx.egui_ctx.set_visuals(visuals);

            Ok(Box::new(app))
        }),
    )
}
