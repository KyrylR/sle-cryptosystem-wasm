use eframe::egui::{self, Event, Key};

#[cfg(target_os = "windows")]
const SHORTCUTS: [&str; 3] = [
    "F1 - показати/сховати допомогу",
    "Ctrl+ - збільшити масштаб",
    "Ctrl- - зменшити масштаб",
];

#[cfg(not(target_os = "windows"))]
const SHORTCUTS: [&str; 3] = [
    "F1 - показати/сховати допомогу",
    "Cmd+ - збільшити масштаб",
    "Cmd- - зменшити масштаб",
];

/// A struct for rendering help information that appears when Tab key is pressed
pub struct HelpPanel {
    visible: bool,
}

impl HelpPanel {
    pub fn new() -> Self {
        Self { visible: false }
    }

    pub fn toggle_visibility(&mut self) {
        self.visible = !self.visible;
    }

    pub fn render(&mut self, ctx: &egui::Context) {
        // Check for input events and show/hide panel if needed
        self.handle_input_events(ctx);

        // Render the "Tab - допомога" text in the bottom right corner
        let screen_rect = ctx.input(|i| i.screen_rect());
        let text = "F1 - навігація";

        // Create text layout using egui's text layout system
        let galley = ctx.fonts(|f| {
            let font_id = egui::FontId::proportional(20.0);
            f.layout_no_wrap(text.to_string(), font_id, egui::Color32::DARK_BLUE)
        });

        let text_rect = egui::Rect::from_min_size(
            egui::pos2(
                screen_rect.max.x - galley.size().x - 10.0,
                screen_rect.max.y - galley.size().y - 10.0,
            ),
            galley.size(),
        );

        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("help_text"),
        ));

        painter.galley(text_rect.min, galley, egui::Color32::DARK_GRAY);

        // Render the help panel when visible
        if self.visible {
            let panel_width = 300.0;
            let line_height = 24.0;
            let panel_height = SHORTCUTS.len() as f32 * line_height + 40.0;

            let panel_rect = egui::Rect::from_min_size(
                egui::pos2(
                    (screen_rect.width() - panel_width) / 2.0,
                    (screen_rect.height() - panel_height) / 2.0,
                ),
                egui::vec2(panel_width, panel_height),
            );

            let panel_painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("help_panel"),
            ));

            // Draw panel background
            panel_painter.rect_filled(
                panel_rect,
                8.0,
                egui::Color32::from_rgba_premultiplied(250, 250, 250, 240),
            );

            // Draw panel border
            panel_painter.rect_stroke(
                panel_rect,
                8.0,
                egui::Stroke::new(1.0, egui::Color32::DARK_GRAY),
                egui::StrokeKind::Middle,
            );

            // Draw panel title
            let title = "Клавіатурні скорочення";
            let title_galley = ctx.fonts(|f| {
                let font_id = egui::FontId::proportional(18.0);
                f.layout_no_wrap(title.to_string(), font_id, egui::Color32::BLACK)
            });

            let title_pos = egui::pos2(
                panel_rect.min.x + (panel_width - title_galley.size().x) / 2.0,
                panel_rect.min.y + 10.0,
            );
            panel_painter.galley(title_pos, title_galley, egui::Color32::BLACK);

            // Draw shortcuts
            for (i, shortcut) in SHORTCUTS.iter().enumerate() {
                let galley = ctx.fonts(|f| {
                    let font_id = egui::FontId::proportional(14.0);
                    f.layout_no_wrap(shortcut.to_string(), font_id, egui::Color32::DARK_GRAY)
                });

                let pos = egui::pos2(
                    panel_rect.min.x + 20.0,
                    panel_rect.min.y + 40.0 + i as f32 * line_height,
                );
                panel_painter.galley(pos, galley, egui::Color32::DARK_GRAY);
            }
        }
    }

    /// Checks for input events and hides/shows the panel
    fn handle_input_events(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            // Look through all events
            for event in &i.events {
                match event {
                    // If any key other than Tab is pressed, hide the panel
                    Event::Key { key, pressed, .. } => {
                        if *key == Key::F1 {
                            if *pressed {
                                // If Tab is pressed, toggle the visibility of the panel
                                self.toggle_visibility();
                            }
                            return;
                        }

                        self.visible = false;
                    }
                    // If mouse button is clicked, hide the panel
                    Event::PointerButton { .. } => {
                        self.visible = false;
                        return;
                    }
                    // If text is entered, hide the panel
                    Event::Text(_) => {
                        self.visible = false;
                        return;
                    }
                    // Ignore other events like hover, focus, etc.
                    _ => {}
                }
            }
        });
    }
}
