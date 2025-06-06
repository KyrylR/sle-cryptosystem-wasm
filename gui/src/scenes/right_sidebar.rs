use eframe::egui;
use eframe::egui::{Align, FontId, Frame, Layout, RichText, TextStyle, Ui};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::gen_keypair_popup::GenKeypairPopup;
use super::gen_keys_popup::GenGPopup;
use super::encrypt_popup::EncryptPopup;
use super::decrypt_popup::DecryptPopup;

use crate::widgets::error_popup::ErrorPopup;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptosystemExport {
    // Generation parameters (a, c, l, k, seed, p, q)
    gen_g_a: u64,
    gen_g_c: u64,
    gen_g_l: u64,
    gen_g_k: u64,
    gen_g_seed: u64,
    equation_count: usize, // p
    variables_count: usize, // q
    // Matrices from private key if available
    matrix_a: Option<sle_crypto::ring::Matrix>,
    matrix_a_bar: Option<sle_crypto::ring::Matrix>,
    matrix_b_inv: Option<sle_crypto::ring::Matrix>,
    vector_a_bar_inner: Option<sle_crypto::ring::Vector>,
    // Good matrix information
    good_matrix_a: Option<sle_crypto::ring::Matrix>,
    good_minor_cols: Option<Vec<usize>>,
    good_a1inv: Option<sle_crypto::ring::Matrix>,
}

pub struct RightSideBarState {
    gen_keys_popup: GenGPopup,
    gen_keypair_popup: GenKeypairPopup,
    encrypt_popup: EncryptPopup,
    decrypt_popup: DecryptPopup,
    current_shared_params: Option<SharedParams>,
    current_private_key: Option<PrivateKey>,
    current_generation_params: Option<CryptosystemExport>,
    is_imported: bool,
    error_popup: ErrorPopup,
}

impl RightSideBarState {
    pub fn setup() -> Self {
        Self {
            gen_keys_popup: GenGPopup::new(),
            gen_keypair_popup: GenKeypairPopup::new(),
            encrypt_popup: EncryptPopup::new(),
            decrypt_popup: DecryptPopup::new(),
            current_shared_params: None,
            current_private_key: None,
            current_generation_params: None,
            is_imported: false,
            error_popup: ErrorPopup::new(),
        }
    }

    fn create_file_dialog(default_filename: &str, title: &str) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_file_name(default_filename)
            .set_title(title)
            .set_can_create_directories(true)
            .add_filter("JSON Files", &["json"])
            .save_file()
    }

    fn open_file_dialog(title: &str) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_title(title)
            .add_filter("JSON Files", &["json"])
            .pick_file()
    }

    fn export_cryptosystem(&self) -> Result<CryptosystemExport, String> {
        let export_data = self.current_generation_params.as_ref()
            .ok_or("Не знайдено параметрів для експорту")?
            .clone();

        Ok(export_data)
    }

    fn import_cryptosystem(&mut self, data: CryptosystemExport) -> Result<(), String> {
        // Try to recreate SharedParams from the export data
        match SharedParams::try_with(
            data.gen_g_a,
            data.gen_g_c, 
            data.gen_g_l,
            data.gen_g_k,
            data.gen_g_seed,
            data.equation_count,
            data.variables_count,
        ) {
            Ok(shared_params) => {
                self.current_shared_params = Some(shared_params);
                self.current_generation_params = Some(data.clone());
                
                // If we have private key data, reconstruct it
                if let (Some(matrix_a), Some(matrix_a_bar), Some(matrix_b_inv), Some(vector_a_bar_inner),
                        Some(good_matrix_a), Some(good_minor_cols), Some(good_a1inv)) = 
                    (&data.matrix_a, &data.matrix_a_bar, &data.matrix_b_inv, &data.vector_a_bar_inner,
                     &data.good_matrix_a, &data.good_minor_cols, &data.good_a1inv) {
                    
                    // Create GoodMatrix
                    let good_matrix = sle_crypto::keypair::keys::GoodMatrix {
                        A: good_matrix_a.clone(),
                        minor_cols: good_minor_cols.clone(),
                        A1inv: good_a1inv.clone(),
                    };
                    
                    // Create PrivateKey
                    let private_key = PrivateKey {
                        shared_params: self.current_shared_params.as_ref().unwrap().clone(),
                        matrix_A: good_matrix,
                        matrix_A_bar: matrix_a_bar.clone(),
                        matrix_B_inv: matrix_b_inv.clone(),
                        vector_A_bar_inner: vector_a_bar_inner.clone(),
                    };
                    
                                    self.current_private_key = Some(private_key);
            }
            
            // Set the imported flag
            self.is_imported = true;
            
            Ok(())
            }
            Err(e) => Err(format!("Помилка відновлення параметрів: {}", e))
        }
    }

    fn handle_export(&mut self) {
        match self.export_cryptosystem() {
            Ok(export_data) => {
                let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                let default_filename = format!("cryptosystem_export_{}.json", timestamp);
                
                if let Some(path) = Self::create_file_dialog(&default_filename, "Експорт параметрів криптосистеми") {
                    match serde_json::to_string_pretty(&export_data) {
                        Ok(json_string) => {
                            if let Err(e) = std::fs::write(&path, json_string) {
                                self.error_popup.show_error_timed(
                                    format!("Помилка запису файлу: {}", e),
                                    5.0
                                );
                            } else {
                                // We'll use the error popup for success messages too, as it's our general notification system
                                self.error_popup.show_error_timed(
                                    format!("✅ Параметри криптосистеми успішно експортовано до {:?}", path.file_name().unwrap_or_default()),
                                    3.0
                                );
                            }
                        }
                        Err(e) => {
                            self.error_popup.show_error_timed(
                                format!("Помилка серіалізації: {}", e),
                                5.0
                            );
                        }
                    }
                }
            }
            Err(e) => {
                self.error_popup.show_error_timed(e, 5.0);
            }
        }
    }

    fn handle_import(&mut self) {
        if let Some(path) = Self::open_file_dialog("Імпорт параметрів криптосистеми") {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str::<CryptosystemExport>(&content) {
                        Ok(import_data) => {
                            match self.import_cryptosystem(import_data) {
                                Ok(()) => {
                                    self.error_popup.show_error_timed(
                                        format!("✅ Параметри криптосистеми успішно імпортовано з {:?}", path.file_name().unwrap_or_default()),
                                        3.0
                                    );
                                }
                                Err(e) => {
                                    self.error_popup.show_error_timed(e, 5.0);
                                }
                            }
                        }
                        Err(e) => {
                            self.error_popup.show_error_timed(
                                format!("Помилка десеріалізації: {}", e),
                                5.0
                            );
                        }
                    }
                }
                Err(e) => {
                    self.error_popup.show_error_timed(
                        format!("Помилка читання файлу: {}", e),
                        5.0
                    );
                }
            }
        }
    }

    pub fn render(&mut self, ui: &mut Ui, ctx: &egui::Context) -> Option<(SharedParams, Option<PrivateKey>)> {
        self.gen_keys_popup.render(ctx);
        self.gen_keypair_popup.render(ctx);
        self.encrypt_popup.render(ctx);
        self.decrypt_popup.render(ctx);
        self.error_popup.update(ctx);

        ui.horizontal(|ui| {
            ui.vertical_centered_justified(|ui| {
                ui.heading(RichText::new("Криптосистема на основі відображень кілець").size(22.0));
                ui.add_space(20.0);

                Frame::default().show(ui, |ui| self.render_sidebar(ui));
            });
        });

        // Check if new shared params were generated
        if let Some(shared_params) = self.gen_keys_popup.take_generated_params() {
            let gen_params = self.gen_keys_popup.get_generation_params();
            
            // Store the generation parameters for export
            self.current_generation_params = Some(CryptosystemExport {
                gen_g_a: gen_params.gen_g_a,
                gen_g_c: gen_params.gen_g_c,
                gen_g_l: gen_params.gen_g_l,
                gen_g_k: gen_params.gen_g_k,
                gen_g_seed: gen_params.gen_g_seed,
                equation_count: gen_params.equation_count,
                variables_count: gen_params.variables_count,
                matrix_a: None,
                matrix_a_bar: None,
                matrix_b_inv: None,
                vector_a_bar_inner: None,
                good_matrix_a: None,
                good_minor_cols: None,
                good_a1inv: None,
            });
            
            self.current_shared_params = Some(shared_params.clone());
            
            return Some((shared_params.clone(), None));
        }
        
        if let Some(private_keys) = self.gen_keypair_popup.take_generated_keypair() {
            self.current_private_key = Some(private_keys.clone());

            // Update generation parameters with private key data if available
            if let Some(ref mut gen_params) = self.current_generation_params {
                gen_params.matrix_a = Some(private_keys.matrix_A.A.clone());
                gen_params.matrix_a_bar = Some(private_keys.matrix_A_bar.clone());
                gen_params.matrix_b_inv = Some(private_keys.matrix_B_inv.clone());
                gen_params.vector_a_bar_inner = Some(private_keys.vector_A_bar_inner.clone());
                gen_params.good_matrix_a = Some(private_keys.matrix_A.A.clone());
                gen_params.good_minor_cols = Some(private_keys.matrix_A.minor_cols.clone());
                gen_params.good_a1inv = Some(private_keys.matrix_A.A1inv.clone());
            }

            let shared_params = self.current_shared_params.clone().unwrap();
            
            return Some((shared_params, Some(private_keys)));
        }

        // Check if parameters were imported
        if self.is_imported {
            self.is_imported = false; // Reset the flag
            
            if let Some(shared_params) = self.current_shared_params.clone() {
                return Some((shared_params, self.current_private_key.clone()));
            }
        }
        
        None
    }

    fn render_sidebar(&mut self, ui: &mut Ui) {
        let style = ui.style_mut();
        style.override_text_style = Some(TextStyle::Body);
        style.override_font_id = Some(FontId::proportional(20.0));

        let layout = Layout::top_down(Align::Center);

        // Gen G button - triggers the popup
        ui.with_layout(layout, |ui| {
            if ui
                .button(RichText::new("Генерація ізоморфізмів кілець (GEN-G)").size(18.0))
                .clicked()
            {
                self.gen_keys_popup.show();
            }
        });

        ui.add_space(15.0);

        // Generate Keys button
        ui.with_layout(layout, |ui| {            
            let button = ui.button(RichText::new("Генерація ключів системи").size(18.0));
            
            if button.clicked() {
                if let Some(shared_params) = self.current_shared_params.clone() {
                    self.gen_keypair_popup.show(shared_params);
                } else {
                    self.error_popup.show_error_timed(
                        "Спочатку потрібно згенерувати ізоморфізми кілець за алгоритмом GEN-G", 
                        5.0
                    );
                }
            }
        });

        ui.add_space(15.0);

        // Encrypt button
        ui.with_layout(layout, |ui| {
            let button = ui.button(RichText::new("Шифрування повідомлення").size(18.0));
            
            if button.clicked() {
                if let Some(shared_params) = self.current_shared_params.clone() {
                    if self.current_private_key.is_some() {
                        self.encrypt_popup.show(shared_params, self.current_private_key.clone());
                    } else {
                        self.error_popup.show_error_timed(
                            "Спочатку потрібно згенерувати ключі системи", 
                            5.0
                        );
                    }
                } else {
                    self.error_popup.show_error_timed(
                        "Спочатку потрібно згенерувати ізоморфізми кілець та ключі системи", 
                        5.0
                    );
                }
            }
        });

        ui.add_space(15.0);

        // Decrypt button
        ui.with_layout(layout, |ui| {
            let button = ui.button(RichText::new("Розшифрування повідомлення").size(18.0));
            
            if button.clicked() {
                if let Some(shared_params) = self.current_shared_params.clone() {
                    if self.current_private_key.is_some() {
                        self.decrypt_popup.show(shared_params, self.current_private_key.clone());
                    } else {
                        self.error_popup.show_error_timed(
                            "Спочатку потрібно згенерувати ключі системи", 
                            5.0
                        );
                    }
                } else {
                    self.error_popup.show_error_timed(
                        "Спочатку потрібно згенерувати ізоморфізми кілець та ключі системи", 
                        5.0
                    );
                }
            }
        });

        ui.add_space(15.0);

        // Import button
        ui.with_layout(layout, |ui| {
            if ui.button(RichText::new("Імпорт параметрів").size(18.0)).clicked() {
                self.handle_import();
            }
        });

        ui.add_space(15.0);

        // Export button
        ui.with_layout(layout, |ui| {
            let button = ui.button(RichText::new("Експорт параметрів").size(18.0));
            
            if button.clicked() {
                if self.current_generation_params.is_some() {
                    self.handle_export();
                } else {
                    self.error_popup.show_error_timed(
                        "Спочатку потрібно згенерувати параметри криптосистеми для експорту",
                        5.0
                    );
                }
            }
        });
    }

    fn display_menu_button(layout: Layout, ui: &mut Ui, text: &str) {
        ui.with_layout(layout, |ui| {
            let _ = ui.button(RichText::new(text).size(18.0));
        });
    }
}
