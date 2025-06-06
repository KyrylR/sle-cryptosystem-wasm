use crate::widgets::error_popup::ErrorPopup;

use eframe::egui;
use eframe::egui::{
    Color32, Frame, Key, Margin, RichText, Ui, Vec2,
    Window,
};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;

#[derive(Clone, Debug)]
pub struct GenKeypairPopup {
    visible: bool,
    shared_params: Option<SharedParams>,
    error_popup: ErrorPopup,
    loading: bool,
    generated_keypair: Option<PrivateKey>,
}

impl GenKeypairPopup {
    pub fn new() -> Self {
        Self {
            visible: false,
            shared_params: None,
            error_popup: ErrorPopup::new(),
            loading: false,
            generated_keypair: None,
        }
    }

    pub fn show(&mut self, shared_params: SharedParams) {
        self.shared_params = Some(shared_params);
        self.visible = true;
        self.generated_keypair = None;
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.loading = false;
        self.shared_params = None;
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn take_generated_keypair(&mut self) -> Option<PrivateKey> {
        self.generated_keypair.take()
    }

    pub fn render(&mut self, ctx: &egui::Context) {
        if !self.visible {
            return;
        }

        self.error_popup.update(ctx);

        let mut open = true;
        Window::new("Генерація системи лінійних рівнянь та ключів")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .fixed_size(Vec2::new(450.0, 300.0))
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
            if let Some(ref params) = self.shared_params {
                ui.label(
                    RichText::new("Параметри ізоморфізмів кілець:")
                        .size(14.0)
                        .color(Color32::DARK_GRAY),
                );
                ui.add_space(10.0);
                
                Frame::group(ui.style())
                    .outer_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.label(format!("Кількість рівнянь (p): {}", params.equation_count));
                        ui.add_space(20.0);
                        ui.label(format!("Кількість змінних (q): {}", params.variables_count));
                        ui.add_space(20.0);
                        ui.label(format!("Модуль кільця Z_k: {}", params.inner_structure.ring.modulus()));
                        ui.add_space(20.0);
                        ui.label(format!("Модуль кільця G_m: {}", params.outer_structure.ring.modulus()));
                    });
                    
                ui.add_space(20.0);
                
                ui.label(
                    RichText::new("Натисніть кнопку для генерації системи рівнянь l(x), L(x) та ключів")
                        .size(14.0)
                        .color(Color32::DARK_GRAY),
                );
            } else {
                ui.label(
                    RichText::new("Помилка: Не знайдено ізоморфізмів кілець")
                        .size(14.0)
                        .color(Color32::RED),
                );
            }

            ui.add_space(30.0);

            // Buttons
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        Vec2::new(100.0, 30.0),
                        egui::Button::new(RichText::new("Скасувати").size(16.0)),
                    )
                    .clicked()
                {
                    self.hide();
                }

                ui.add_space(10.0);

                let generate_enabled = self.shared_params.is_some();
                let generate_clicked = ui
                    .add_enabled_ui(generate_enabled, |ui| {
                        ui.add_sized(
                            Vec2::new(150.0, 30.0),
                            egui::Button::new(RichText::new("Згенерувати систему рівнянь").size(16.0)),
                        )
                    })
                    .inner
                    .clicked();

                let enter_pressed = ctx.input(|i| i.key_pressed(Key::Enter)) && generate_enabled;

                if generate_clicked || enter_pressed {
                    self.handle_generate();
                }
            });
        });
    }

    fn render_loading(&mut self, ui: &mut Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(50.0);
            ui.heading("Генерація системи лінійних рівнянь...");
            ui.add_space(10.0);
            ui.label(
                RichText::new("Будь ласка, зачекайте, поки генеруються система рівнянь l(x), L(x) та ключі")
                    .size(14.0)
                    .color(Color32::DARK_GRAY),
            );
            ui.add_space(20.0);
            ui.spinner();
            ui.add_space(50.0);
        });
    }

    fn handle_generate(&mut self) {
        let Some(shared_params) = self.shared_params.clone() else {
            self.error_popup.show_error_timed("Помилка: Не знайдено ізоморфізмів кілець", 5.0);
            return;
        };

        // Start loading state
        self.loading = true;

        // Try to generate PrivateKey and PublicKey
        match PrivateKey::try_with(shared_params.clone()) {
            Ok(private_key) => {
                self.generated_keypair = Some(private_key);
                self.loading = false;
                self.hide();
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
                        format!("Невідповідність розмірностей: {}", msg)
                    }
                    sle_crypto::errors::SLECryptoError::NoInverse(msg) => {
                        format!("Неможливо знайти обернений елемент: {}", msg)
                    }
                    sle_crypto::errors::SLECryptoError::InvalidModulus(msg) => {
                        format!("Невірний модуль: {}", msg)
                    }
                    _ => {
                        format!("Невідома помилка при генерації системи рівнянь: {}", e)
                    }
                };
                self.error_popup.show_error_timed(error_message, 7.0);
            }
        }
    }
} 