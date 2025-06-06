use eframe::egui::*;

/// Error popup widget with absolute positioning
#[derive(Clone, Debug)]
pub struct ErrorPopup {
    pub visible: bool,
    pub title: String,
    pub message: String,
    pub position: Option<Pos2>,
    pub auto_close_timer: Option<f32>,
    start_time: Option<f64>,
}

impl Default for ErrorPopup {
    fn default() -> Self {
        Self {
            visible: false,
            title: "Помилка".to_string(),
            message: String::new(),
            position: None,
            auto_close_timer: None,
            start_time: None,
        }
    }
}

impl ErrorPopup {
    /// Create a new error popup
    pub fn new() -> Self {
        Self::default()
    }

    /// Show the error popup with a message
    pub fn show_error(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.title = "Помилка".to_string();
        self.visible = true;
        self.start_time = None;
    }

    /// Show error popup with auto-close timer (seconds)
    pub fn show_error_timed(&mut self, message: impl Into<String>, duration_secs: f32) {
        self.show_error(message);
        self.auto_close_timer = Some(duration_secs);
    }

    /// Hide the popup
    pub fn hide(&mut self) {
        self.visible = false;
        self.position = None;
        self.auto_close_timer = None;
        self.start_time = None;
    }

    /// Update and render the popup (call this in your main UI loop)
    pub fn update(&mut self, ctx: &Context) {
        if !self.visible {
            return;
        }

        // Handle auto-close timer
        if let Some(duration) = self.auto_close_timer {
            if self.start_time.is_none() {
                self.start_time = Some(ctx.input(|i| i.time));
            }

            if let Some(start) = self.start_time {
                let elapsed = ctx.input(|i| i.time) - start;
                if elapsed >= duration as f64 {
                    self.hide();
                    return;
                }
            }
        }

        // Create the popup window
        let mut open = true;
        let window = Window::new(&self.title)
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .anchor(Align2::RIGHT_TOP, Vec2::new(-20.0, 20.0))
            .auto_sized()
            .frame(Frame::popup(&ctx.style()));

        // Apply custom position if specified
        let window = if let Some(pos) = self.position {
            window.fixed_pos(pos)
        } else {
            window
        };

        window.show(ctx, |ui| {
            ui.set_min_width(300.0);
            ui.set_max_width(400.0);

            // Error icon and message
            ui.horizontal(|ui| {
                // Error icon (red circle with X)
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
                ui.painter().circle_filled(
                    rect.center(),
                    12.0,
                    Color32::from_rgb(220, 53, 69), // Bootstrap danger red
                );
                ui.painter().text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    "✕",
                    FontId::proportional(16.0),
                    Color32::WHITE,
                );

                ui.add_space(10.0);

                // Message text
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&self.message)
                            .size(18.0)
                            .color(Color32::BLACK),
                    );
                });
            });

            ui.add_space(15.0);

            // Buttons
            ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                let button = ui.add_sized(
                    Vec2::new(80.0, 30.0),
                    Button::new(RichText::new("Закрити").size(14.0)),
                );
                if button.clicked() {
                    self.hide();
                }
            });
        });

        // Handle window close button
        if !open {
            self.hide();
        }

        // Request repaint for auto-close timer
        if self.auto_close_timer.is_some() {
            ctx.request_repaint();
        }
    }
}
