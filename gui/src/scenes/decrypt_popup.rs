use crate::widgets::error_popup::ErrorPopup;

use eframe::egui;
use eframe::egui::{
    Color32, FontId, Frame, Key, Margin, RichText, ScrollArea, TextEdit, TextStyle, Ui, Vec2,
    Window,
};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;
use sle_crypto::ring::Vector;

#[derive(Clone, Debug)]
pub struct DecryptPopup {
    visible: bool,
    shared_params: Option<SharedParams>,
    private_key: Option<PrivateKey>,
    input_text: String,
    output_text: String,
    error_popup: ErrorPopup,
    loading: bool,
}

impl DecryptPopup {
    pub fn new() -> Self {
        Self {
            visible: false,
            shared_params: None,
            private_key: None,
            input_text: String::new(),
            output_text: String::new(),
            error_popup: ErrorPopup::new(),
            loading: false,
        }
    }

    pub fn show(&mut self, shared_params: SharedParams, private_key: Option<PrivateKey>) {
        if private_key.is_some() {
            self.shared_params = Some(shared_params);
            self.private_key = private_key;
            self.visible = true;
            self.input_text.clear();
            self.output_text.clear();
        } else {
            self.error_popup.show_error_timed(
                "Для розшифрування потрібна система лінійних рівнянь",
                5.0,
            );
        }
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.loading = false;
        self.shared_params = None;
        self.private_key = None;
        self.input_text.clear();
        self.output_text.clear();
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn render(&mut self, ctx: &egui::Context) {
        if !self.visible {
            return;
        }

        self.error_popup.update(ctx);

        let mut open = true;
        Window::new("Розшифрування блоку повідомлення за системою L(x)")
            .open(&mut open)
            .resizable(true)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .default_size(Vec2::new(600.0, 500.0))
            .show(ctx, |ui| {
                self.render_content(ui, ctx);
            });

        if !open {
            self.hide();
        }
    }

    fn render_content(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        if self.loading {
            self.render_loading(ui);
            return;
        }

        ui.vertical_centered_justified(|ui| {
            if let (Some(params), Some(_private_key)) = (&self.shared_params, &self.private_key) {
                ui.label(
                    RichText::new("Параметри системи лінійних рівнянь:")
                        .size(14.0)
                        .color(Color32::DARK_GRAY),
                );
                ui.add_space(5.0);
                
                Frame::group(ui.style())
                    .outer_margin(Margin::same(5))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!("Розмір блоку повідомлення: {} елементів", params.equation_count));
                            ui.separator();
                            ui.label(format!("Змінних у системі: {}", params.variables_count));
                        });
                    });
                    
                ui.add_space(15.0);
                
                // Input text area
                ui.label(
                    RichText::new("Введіть зашифрований блок (d, d1) у форматі [[vector1], [vector2]]:")
                        .size(14.0)
                        .color(Color32::DARK_GRAY),
                );
                ui.add_space(5.0);
                
                let input_response = ui.add_sized(
                    Vec2::new(ui.available_width(), 80.0),
                    TextEdit::multiline(&mut self.input_text)
                        .font(FontId::monospace(12.0))
                        .hint_text("Наприклад: [[1, 2], [3, 4]]")
                );

                ui.add_space(15.0);

                // Decrypt button
                let decrypt_enabled = !self.input_text.trim().is_empty();
                let decrypt_clicked = ui
                    .add_enabled_ui(decrypt_enabled, |ui| {
                        ui.add_sized(
                            Vec2::new(150.0, 30.0),
                            egui::Button::new(RichText::new("Розшифрувати блок").size(16.0)),
                        )
                    })
                    .inner
                    .clicked();

                let enter_pressed = ctx.input(|i| i.key_pressed(Key::Enter)) && decrypt_enabled;

                if decrypt_clicked || enter_pressed {
                    self.handle_decrypt();
                }

                ui.add_space(15.0);

                // Output area
                if !self.output_text.is_empty() {
                    ui.label(
                        RichText::new("Розшифрований вектор повідомлення:")
                            .size(14.0)
                            .color(Color32::DARK_GRAY),
                    );
                    ui.add_space(5.0);
                    
                    let output_response = ui.add_sized(
                        Vec2::new(ui.available_width(), 60.0),
                        TextEdit::multiline(&mut self.output_text)
                            .font(FontId::monospace(14.0))
                            .interactive(true)
                    );

                    ui.add_space(10.0);
                    
                    // Copy button
                    if ui
                        .add_sized(
                            Vec2::new(120.0, 25.0),
                            egui::Button::new(RichText::new("Копіювати").size(14.0)),
                        )
                        .clicked()
                    {
                        ui.output_mut(|o| o.copied_text = self.output_text.clone());
                    }
                }

            } else {
                ui.label(
                    RichText::new("Помилка: Не знайдено системи лінійних рівнянь або приватного ключа")
                        .size(14.0)
                        .color(Color32::RED),
                );
            }

            ui.add_space(20.0);

            // Close button
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        Vec2::new(100.0, 30.0),
                        egui::Button::new(RichText::new("Закрити").size(16.0)),
                    )
                    .clicked()
                {
                    self.hide();
                }
            });
        });
    }

    fn render_loading(&mut self, ui: &mut Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(50.0);
            ui.heading("Розшифрування блоку...");
            ui.add_space(10.0);
            ui.label(
                RichText::new("Будь ласка, зачекайте, поки блок повідомлення розшифровується")
                    .size(14.0)
                    .color(Color32::DARK_GRAY),
            );
            ui.add_space(20.0);
            ui.spinner();
            ui.add_space(50.0);
        });
    }

    fn handle_decrypt(&mut self) {
        let Some(private_key) = self.private_key.clone() else {
            self.error_popup.show_error_timed("Помилка: Не знайдено приватного ключа", 5.0);
            return;
        };

        if self.input_text.trim().is_empty() {
            self.error_popup.show_error_timed("Введіть зашифрований блок для розшифрування", 3.0);
            return;
        }

        // Parse input format [[vector1], [vector2]]
        let input_text = self.input_text.trim();
        
        // Remove outer brackets
        if !input_text.starts_with('[') || !input_text.ends_with(']') {
            self.error_popup.show_error_timed("Неправильний формат. Очікується [[vector1], [vector2]]", 5.0);
            return;
        }
        
        let inner_content = &input_text[1..input_text.len()-1];
        
        // Find the two inner vectors
        let mut bracket_count = 0;
        let mut first_vector_end = 0;
        let chars: Vec<char> = inner_content.chars().collect();
        
        for (i, &ch) in chars.iter().enumerate() {
            match ch {
                '[' => bracket_count += 1,
                ']' => {
                    bracket_count -= 1;
                    if bracket_count == 0 {
                        first_vector_end = i + 1;
                        break;
                    }
                },
                _ => {}
            }
        }
        
        if first_vector_end == 0 {
            self.error_popup.show_error_timed("Неправильний формат. Не знайдено першого вектору", 5.0);
            return;
        }
        
        let first_vector_str = &inner_content[..first_vector_end];
        let remaining = &inner_content[first_vector_end..].trim_start_matches(',').trim();
        
        // Parse first vector
        if !first_vector_str.starts_with('[') || !first_vector_str.ends_with(']') {
            self.error_popup.show_error_timed("Неправильний формат першого вектору", 5.0);
            return;
        }
        
        let first_nums_str = &first_vector_str[1..first_vector_str.len()-1];
        let input_vector1: Result<Vector, _> = first_nums_str
            .split(',')
            .map(|s| s.trim().parse::<i64>())
            .collect();
            
        let input_vector1 = match input_vector1 {
            Ok(vec) => vec,
            Err(_) => {
                self.error_popup.show_error_timed("Неправильний формат першого вектору. Використовуйте числа через кому.", 5.0);
                return;
            }
        };
        
        // Parse second vector
        if !remaining.starts_with('[') || !remaining.ends_with(']') {
            self.error_popup.show_error_timed("Неправильний формат другого вектору", 5.0);
            return;
        }
        
        let second_nums_str = &remaining[1..remaining.len()-1];
        let input_vector2: Result<Vector, _> = second_nums_str
            .split(',')
            .map(|s| s.trim().parse::<i64>())
            .collect();
            
        let input_vector2 = match input_vector2 {
            Ok(vec) => vec,
            Err(_) => {
                self.error_popup.show_error_timed("Неправильний формат другого вектору. Використовуйте числа через кому.", 5.0);
                return;
            }
        };

        let expected_size = self.shared_params.as_ref().unwrap().equation_count;
        if input_vector1.len() != expected_size {
            self.error_popup.show_error_timed(
                &format!("Розмір першого вектору повинен бути {} чисел", expected_size), 
                5.0
            );
            return;
        }

        if input_vector2.len() != expected_size {
            self.error_popup.show_error_timed(
                &format!("Розмір другого вектору повинен бути {} чисел", expected_size), 
                5.0
            );
            return;
        }

        // Start loading state
        self.loading = true;

        // Try to decrypt the vectors
        match private_key.decrypt_block((input_vector1, input_vector2)) {
            Ok(result_vector) => {
                self.output_text = format!("[{}]", result_vector.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
                self.loading = false;
            }
            Err(e) => {
                self.loading = false;
                let error_message = match e {
                    sle_crypto::errors::SLECryptoError::InvalidParameters(msg) => {
                        format!("Невірні параметри: {}", msg)
                    }
                    sle_crypto::errors::SLECryptoError::InternalError(msg) => {
                        format!("Внутрішня помилка: {}", msg)
                    }
                    sle_crypto::errors::SLECryptoError::DimensionMismatch(msg) => {
                        format!("Невідповідність розмірів: {}", msg)
                    }
                    _ => format!("Помилка розшифрування: {}", e),
                };
                self.error_popup.show_error_timed(&error_message, 5.0);
            }
        }
    }
} 