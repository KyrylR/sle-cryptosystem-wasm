use eframe::egui;
use eframe::egui::{Align, FontId, Frame, Layout, RichText, TextStyle, Ui, ScrollArea};
use sle_crypto::keypair::keys::PrivateKey;
use sle_crypto::keypair::shared_params::SharedParams;
use sle_crypto::ring::{Matrix, Vector};

pub struct MainContentState {}

impl MainContentState {
    pub fn setup() -> Self {
        Self {}
    }

    pub fn render(&mut self, ui: &mut Ui, _ctx: &egui::Context, shared_params: &Option<SharedParams>, private_key: &Option<PrivateKey>) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new("Параметри криптосистеми на основі відображень кілець").size(24.0));
                ui.add_space(20.0);

                // Shared Parameters Section
                Frame::default().show(ui, |ui| {
                    if let Some(params) = shared_params {
                        self.render_shared_params(ui, params);
                    } else {
                        self.render_no_params(ui);
                    }
                });

                ui.add_space(30.0);

                // Private and Public Key Section
                if let Some(private_key) = private_key {
                    Frame::default().show(ui, |ui| {
                        self.render_key_information(ui, private_key);
                    });
                }
            });
        });

        ui.separator();
    }

    fn render_shared_params(&self, ui: &mut Ui, params: &SharedParams) {
        let style = ui.style_mut();
        style.override_text_style = Some(TextStyle::Body);
        style.override_font_id = Some(FontId::proportional(16.0));

        ui.vertical(|ui| {
            // Row 1: Basic parameters
            ui.horizontal(|ui| {
                ui.label(RichText::new("Кількість рівнянь (p):").size(18.0).strong());
                ui.label(RichText::new(format!("{}", params.equation_count)).size(18.0));
                ui.separator();
                ui.label(RichText::new("Кількість змінних (q):").size(18.0).strong());
                ui.label(RichText::new(format!("{}", params.variables_count)).size(18.0));
            });

            ui.add_space(20.0);

            // Row 2: Inner structure (Z_k)
            ui.label(RichText::new("Ізоморфізм для кільця Z_k (внутрішня структура):").size(20.0).strong());
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label(RichText::new("Модуль кільця:").size(16.0).strong());
                ui.label(RichText::new(format!("{}", params.inner_structure.ring.modulus())).size(16.0));
            });
            
            self.render_isomorphism_table(ui, &params.inner_structure.definite_string, "inner");

            ui.add_space(20.0);

            // Row 3: Outer structure (G_m)
            ui.label(RichText::new("Ізоморфізм для кільця G_m (зовнішня структура):").size(20.0).strong());
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label(RichText::new("Модуль кільця:").size(16.0).strong());
                ui.label(RichText::new(format!("{}", params.outer_structure.ring.modulus())).size(16.0));
            });
            
            self.render_isomorphism_table(ui, &params.outer_structure.definite_string, "outer");
            
            ui.add_space(20.0);

            // Row 4: ksi_1 vector
            ui.label(RichText::new("Вектор ξ₁ (відображення G_m → G_k/ψ):").size(20.0).strong());
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label(RichText::new("Розмір вектору:").size(16.0).strong());
                ui.label(RichText::new(format!("{}", params.ksi_1.len())).size(16.0));
            });
            
            self.render_isomorphism_table(ui, &params.ksi_1, "ksi_1_vector");

            ui.add_space(20.0);
        });
    }

    fn render_isomorphism_table(&self, ui: &mut Ui, definite_string: &[i64], table_type: &str) {
        ui.add_space(10.0);
        
        ScrollArea::both()
            .id_salt(format!("{}_scroll_area", table_type))
            .min_scrolled_height(300.0)
            .max_height(300.0)
            .show(ui, |ui| {
                // Calculate optimal number of columns based on available width
                let available_width = ui.available_width();
                let cell_width = 40.0; // Approximate width per cell
                let max_cols = ((available_width / cell_width) as usize).max(10).min(20);
                
                egui::Grid::new(format!("{}_table", table_type))
                    .striped(true)
                    .show(ui, |ui| {
                        // Display all indices and values in rows
                        let total_elements = definite_string.len();
                        
                        for chunk_start in (0..total_elements).step_by(max_cols) {
                            let chunk_end = (chunk_start + max_cols).min(total_elements);
                            
                            // First row of this chunk: indices
                            for i in chunk_start..chunk_end {
                                ui.label(RichText::new(format!("{}", i)).size(14.0));
                            }
                            ui.end_row();
                            
                            // Second row of this chunk: definite_string values
                            for i in chunk_start..chunk_end {
                                ui.label(RichText::new(format!("{}", definite_string[i])).size(14.0));
                            }
                            ui.end_row();
                            
                            // Add some spacing between chunks if not the last chunk
                            if chunk_end < total_elements {
                                ui.end_row(); // Empty row for spacing
                            }
                        }
                    });
            });
    }

    fn render_no_params(&self, ui: &mut Ui) {
        let style = ui.style_mut();
        style.override_text_style = Some(TextStyle::Body);
        style.override_font_id = Some(FontId::proportional(20.0));

        let layout = Layout::top_down(Align::LEFT);

        ui.with_layout(layout, |ui| {
            Self::display_main_text(layout, ui, "Ізоморфізми кілець не згенеровані");

            ui.add_space(10.0);

            Self::display_main_text(layout, ui, "Перейдіть до 'Генерація ізоморфізмів кілець (GEN-G)' для створення параметрів криптосистеми");
        });
    }

    fn display_main_text(layout: Layout, ui: &mut Ui, text: &str) {
        ui.with_layout(layout, |ui| {
            ui.label(RichText::new(text).size(18.0));
        });
    }

    fn render_key_information(&self, ui: &mut Ui, private_key: &PrivateKey) {
        ui.vertical(|ui| {
            ui.heading(RichText::new("Система лінійних рівнянь та ключі").size(22.0));
            ui.add_space(15.0);

            // Generate public key
            let public_key = match private_key.get_public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    ui.label(RichText::new(format!("Помилка генерації публічного ключа: {}", e)).color(egui::Color32::RED));
                    return;
                }
            };

            // Private Key Section
            ui.label(RichText::new("Приватні параметри системи:").size(20.0).strong());
            ui.add_space(10.0);

            // l(x) - matrix_A
            ui.label(RichText::new("Матриця системи l(x):").size(18.0).strong());
            ui.add_space(5.0);
            self.render_matrix(ui, &private_key.matrix_A.A, "private_l_matrix");
            ui.add_space(15.0);

            // L(x) - matrix_A_bar + vector_A_bar_inner
            ui.label(RichText::new("Афінне перетворення L(x):").size(18.0).strong());
            ui.add_space(5.0);
            ui.label(RichText::new("Матриця B·A:").size(16.0));
            self.render_matrix(ui, &private_key.matrix_A_bar, "private_L_matrix");
            ui.add_space(10.0);
            ui.label(RichText::new("Вектор зсуву a:").size(16.0));
            self.render_vector(ui, &private_key.vector_A_bar_inner, "private_L_vector");

            ui.add_space(25.0);

            // Public Key Section
            ui.label(RichText::new("Публічні параметри системи:").size(20.0).strong());
            ui.add_space(10.0);

            // pub l(x) - matrix_A_factored
            ui.label(RichText::new("Публічна система l'(x) у G_k/ψ:").size(18.0).strong());
            ui.add_space(5.0);
            self.render_matrix(ui, &public_key.matrix_A_factored, "public_l_matrix");
            ui.add_space(15.0);

            // pub L(x) - matrix_A_bar_factored + vector_A_bar_inner_factored
            ui.label(RichText::new("Публічне афінне перетворення L'(x) у G_k/ψ:").size(18.0).strong());
            ui.add_space(5.0);
            ui.label(RichText::new("Матриця:").size(16.0));
            self.render_matrix(ui, &public_key.matrix_A_bar_factored, "public_L_matrix");
            ui.add_space(10.0);
            ui.label(RichText::new("Вектор:").size(16.0));
            self.render_vector(ui, &public_key.vector_A_bar_inner_factored, "public_L_vector");
        });
    }

    fn render_matrix(&self, ui: &mut Ui, matrix: &Matrix, id: &str) {
        ScrollArea::horizontal()
            .id_salt(format!("{}_scroll", id))
            .show(ui, |ui| {
                egui::Grid::new(id)
                    .striped(true)
                    .spacing([5.0, 2.0])
                    .show(ui, |ui| {
                        for (row_idx, row) in matrix.iter().enumerate() {
                            // Row label
                            ui.label(RichText::new(format!("Ряд {}:", row_idx)).size(12.0));
                            
                            // Matrix elements
                            for &element in row {
                                ui.label(RichText::new(format!("{}", element)).size(12.0).monospace());
                            }
                            ui.end_row();
                        }
                    });
            });
    }

    fn render_vector(&self, ui: &mut Ui, vector: &Vector, id: &str) {
        ScrollArea::horizontal()
            .id_salt(format!("{}_scroll", id))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("[").size(14.0));
                    for (i, &element) in vector.iter().enumerate() {
                        if i > 0 {
                            ui.label(RichText::new(",").size(14.0));
                        }
                        ui.label(RichText::new(format!("{}", element)).size(14.0).monospace());
                    }
                    ui.label(RichText::new("]").size(14.0));
                });
            });
    }
}
