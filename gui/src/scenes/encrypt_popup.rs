use crate::widgets::error_popup::ErrorPopup;

use eframe::egui;
use eframe::egui::{
    Color32, FontId, Frame, Key, Margin, RichText, ScrollArea, TextEdit, TextStyle, Ui, Vec2,
    Window,
};
use sle_crypto::keypair::keys::{PrivateKey, PublicKey};
use sle_crypto::keypair::shared_params::SharedParams;
use sle_crypto::ring::Vector;

#[derive(Clone, Debug)]
pub struct EncryptPopup {
    visible: bool,
    shared_params: Option<SharedParams>,
    private_key: Option<PrivateKey>,
    public_key: Option<PublicKey>,
    input_text: String,
    output_text: String,
    error_popup: ErrorPopup,
    loading: bool,
}

impl EncryptPopup {
    pub fn new() -> Self {
        Self {
            visible: false,
            shared_params: None,
            private_key: None,
            public_key: None,
            input_text: String::new(),
            output_text: String::new(),
            error_popup: ErrorPopup::new(),
            loading: false,
        }
    }

    pub fn show(&mut self, shared_params: SharedParams, private_key: Option<PrivateKey>) {
        if let Some(ref pk) = private_key {
            match pk.get_public_key() {
                Ok(public_key) => {
                    self.shared_params = Some(shared_params);
                    self.private_key = private_key;
                    self.public_key = Some(public_key);
                    self.visible = true;
                    self.input_text.clear();
                    self.output_text.clear();
                }
                Err(e) => {
                    self.error_popup.show_error_timed(
                        &format!("Помилка створення публічних параметрів: {}", e),
                        5.0,
                    );
                }
            }
        } else {
            self.error_popup.show_error_timed(
                "Для шифрування потрібна система лінійних рівнянь",
                5.0,
            );
        }
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.loading = false;
        self.shared_params = None;
        self.private_key = None;
        self.public_key = None;
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
        Window::new("Шифрування блоку повідомлення за системою l(x)")
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
            if let (Some(params), Some(_public_key)) = (&self.shared_params, &self.public_key) {
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
                    RichText::new(&format!("Введіть вектор повідомлення ({} чисел через кому):", params.equation_count))
                        .size(14.0)
                        .color(Color32::DARK_GRAY),
                );
                ui.add_space(5.0);
                
                let input_response = ui.add_sized(
                    Vec2::new(ui.available_width(), 60.0),
                    TextEdit::multiline(&mut self.input_text)
                        .font(FontId::monospace(14.0))
                        .hint_text("Наприклад: 1, 2, 3")
                );

                ui.add_space(15.0);

                // Encrypt button
                let encrypt_enabled = !self.input_text.trim().is_empty();
                let encrypt_clicked = ui
                    .add_enabled_ui(encrypt_enabled, |ui| {
                        ui.add_sized(
                            Vec2::new(150.0, 30.0),
                            egui::Button::new(RichText::new("Зашифрувати блок").size(16.0)),
                        )
                    })
                    .inner
                    .clicked();

                let enter_pressed = ctx.input(|i| i.key_pressed(Key::Enter)) && encrypt_enabled;

                if encrypt_clicked || enter_pressed {
                    self.handle_encrypt();
                }

                ui.add_space(15.0);

                // Output area
                if !self.output_text.is_empty() {
                    ui.label(
                        RichText::new("Результат шифрування (d, d1):")
                            .size(14.0)
                            .color(Color32::DARK_GRAY),
                    );
                    ui.add_space(5.0);
                    
                    let output_response = ui.add_sized(
                        Vec2::new(ui.available_width(), 80.0),
                        TextEdit::multiline(&mut self.output_text)
                            .font(FontId::monospace(12.0))
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
                    RichText::new("Помилка: Не знайдено системи лінійних рівнянь або ключів")
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
            ui.heading("Шифрування блоку...");
            ui.add_space(10.0);
            ui.label(
                RichText::new("Будь ласка, зачекайте, поки блок повідомлення шифрується")
                    .size(14.0)
                    .color(Color32::DARK_GRAY),
            );
            ui.add_space(20.0);
            ui.spinner();
            ui.add_space(50.0);
        });
    }

    fn handle_encrypt(&mut self) {
        let Some(shared_params) = self.shared_params.clone() else {
            self.error_popup.show_error_timed("Помилка: Не знайдено системи лінійних рівнянь", 5.0);
            return;
        };

        let Some(public_key) = self.public_key.clone() else {
            self.error_popup.show_error_timed("Помилка: Не знайдено публічного ключа", 5.0);
            return;
        };

        if self.input_text.trim().is_empty() {
            self.error_popup.show_error_timed("Введіть вектор повідомлення для шифрування", 3.0);
            return;
        }

        // Parse input vector
        let input_vector: Result<Vector, _> = self.input_text
            .split(',')
            .map(|s| s.trim().parse::<i64>())
            .collect();

        let input_vector = match input_vector {
            Ok(vec) => vec,
            Err(_) => {
                self.error_popup.show_error_timed("Неправильний формат вектору. Використовуйте числа через кому.", 5.0);
                return;
            }
        };

        if input_vector.len() != shared_params.equation_count {
            self.error_popup.show_error_timed(
                &format!("Розмір вектору повинен бути {} чисел", shared_params.equation_count), 
                5.0
            );
            return;
        }

        // Start loading state
        self.loading = true;

        // Try to encrypt the vector
        match shared_params.encrypt_block(&public_key, &input_vector) {
            Ok((d, d1)) => {
                // Format as [[vector1], [vector2]]
                let d_str = format!("[{}]", d.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
                let d1_str = format!("[{}]", d1.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
                self.output_text = format!("[{}, {}]", d_str, d1_str);
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
                    _ => format!("Помилка шифрування: {}", e),
                };
                self.error_popup.show_error_timed(&error_message, 5.0);
            }
        }
    }
} 