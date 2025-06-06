use crate::widgets::error_popup::ErrorPopup;

use eframe::egui;
use eframe::egui::{
    Color32, FontId, Frame, Key, Margin, RichText, TextEdit, TextStyle, Ui, Vec2,
    Window,
};
use sle_crypto::keypair::shared_params::SharedParams;
use sle_crypto::ring::gcd;

#[derive(Clone, Debug)]
pub struct GenGParams {
    pub gen_g_a: u64,
    pub gen_g_c: u64,
    pub gen_g_l: u64,
    pub gen_g_k: u64,
    pub gen_g_seed: u64,
    pub equation_count: usize,
    pub variables_count: usize,
}

impl Default for GenGParams {
    fn default() -> Self {
        Self {
            gen_g_a: 7,
            gen_g_c: 5,
            gen_g_l: 2,
            gen_g_k: 65,
            gen_g_seed: 12345,
            equation_count: 2,
            variables_count: 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenGPopup {
    visible: bool,
    params: GenGParams,
    // String representations for input fields
    gen_g_a_str: String,
    gen_g_c_str: String,
    gen_g_l_str: String,
    gen_g_k_str: String,
    gen_g_seed_str: String,
    equation_count_str: String,
    variables_count_str: String,
    error_popup: ErrorPopup,
    loading: bool,
    generated_params: Option<SharedParams>,
}

impl GenGPopup {
    pub fn new() -> Self {
        let params = GenGParams::default();
        Self {
            visible: false,
            gen_g_a_str: params.gen_g_a.to_string(),
            gen_g_c_str: params.gen_g_c.to_string(),
            gen_g_l_str: params.gen_g_l.to_string(),
            gen_g_k_str: params.gen_g_k.to_string(),
            gen_g_seed_str: params.gen_g_seed.to_string(),
            equation_count_str: params.equation_count.to_string(),
            variables_count_str: params.variables_count.to_string(),
            params,
            error_popup: ErrorPopup::new(),
            loading: false,
            generated_params: None,
        }
    }

    pub fn show(&mut self) {
        self.visible = true;
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.loading = false;
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn take_generated_params(&mut self) -> Option<SharedParams> {
        self.generated_params.take()
    }

    pub fn get_generation_params(&self) -> GenGParams {
        self.params.clone()
    }

    pub fn render(&mut self, ctx: &egui::Context) {
        if !self.visible {
            return;
        }

        self.error_popup.update(ctx);

        let mut open = true;
        Window::new("Генерація ізоморфізмів кілець (Алгоритм GEN-G)")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .fixed_size(Vec2::new(450.0, 600.0))
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
            ui.label(
                RichText::new("Налаштування параметрів алгоритму GEN-G")
                    .size(14.0)
                    .color(Color32::DARK_GRAY),
            );
            ui.add_space(15.0);

            Frame::group(ui.style())
                .outer_margin(Margin::same(20))
                .show(ui, |ui| self.render_params_form(ui, ctx));
        });
    }

    fn render_loading(&mut self, ui: &mut Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(50.0);
            ui.heading("Генерація ізоморфізмів кілець...");
            ui.add_space(10.0);
            ui.label(
                RichText::new("Будь ласка, зачекайте, поки алгоритм GEN-G генерує ізоморфізми кілець")
                    .size(14.0)
                    .color(Color32::DARK_GRAY),
            );
            ui.add_space(20.0);
            ui.spinner();
            ui.add_space(50.0);
        });
    }

    fn render_params_form(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let style = ui.style_mut();
        style.override_text_style = Some(TextStyle::Body);
        style.override_font_id = Some(FontId::proportional(16.0));
        
        Self::display_label(ui, "Коефіцієнт 'a' функції f(i) = a·i + c");
        Self::display_input(ui, &mut self.gen_g_a_str, "7");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Коефіцієнт 'c' функції f(i) = a·i + c");
        Self::display_input(ui, &mut self.gen_g_c_str, "5");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Параметр 'l' (k = l·m)");
        Self::display_input(ui, &mut self.gen_g_l_str, "2");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Порядок кільця 'k' (НСД(a, k) = 1)");
        Self::display_input(ui, &mut self.gen_g_k_str, "65");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Зерно для псевдовипадкових перетворень");
        Self::display_input(ui, &mut self.gen_g_seed_str, "12345");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Кількість рівнянь системи (p)");
        Self::display_input(ui, &mut self.equation_count_str, "2");
        ui.add_space(10.0);
        
        Self::display_label(ui, "Кількість змінних системи (q ≥ p)");
        Self::display_input(ui, &mut self.variables_count_str, "4");
        ui.add_space(20.0);

        // Buttons
        ui.horizontal(|ui| {
            if ui
                .add_sized(
                    Vec2::new(100.0, 30.0),
                    egui::Button::new(RichText::new("Відміна").size(16.0)),
                )
                .clicked()
            {
                self.hide();
            }

            ui.add_space(10.0);

            let generate_clicked = ui
                .add_sized(
                    Vec2::new(120.0, 30.0),
                    egui::Button::new(RichText::new("Згенерувати ізоморфізми").size(16.0)),
                )
                .clicked();

            let enter_pressed = ctx.input(|i| i.key_pressed(Key::Enter));

            if generate_clicked || enter_pressed {
                self.handle_generate();
            }
        });
    }

    fn display_label(ui: &mut Ui, text: &str) {
        ui.label(RichText::new(text).size(14.0));
    }

    fn display_input(ui: &mut Ui, dst: &mut String, hint: &str) {
        ui.add(
            TextEdit::singleline(dst)
                .hint_text(RichText::new(hint).color(Color32::from_gray(128)))
                .frame(true)
                .margin(Margin::symmetric(10, 5))
                .desired_width(300.0),
        );
    }

    fn handle_generate(&mut self) {
        // Parse input parameters
        if let Err(error_msg) = self.parse_and_validate_params() {
            self.error_popup.show_error_timed(error_msg, 5.0);
            return;
        }

        // Start loading state
        self.loading = true;

        // Try to generate SharedParams
        match SharedParams::try_with(
            self.params.gen_g_a,
            self.params.gen_g_c,
            self.params.gen_g_l,
            self.params.gen_g_k,
            self.params.gen_g_seed,
            self.params.equation_count,
            self.params.variables_count,
        ) {
            Ok(shared_params) => {
                self.generated_params = Some(shared_params);
                self.loading = false;
                self.hide();
            }
            Err(e) => {
                self.loading = false;
                self.error_popup
                    .show_error_timed(format!("Не вдалося згенерувати ізоморфізми кілець: {}", e), 7.0);
            }
        }
    }

    fn parse_and_validate_params(&mut self) -> Result<(), String> {
        // Parse gen_g_a
        self.params.gen_g_a = self
            .gen_g_a_str
            .parse::<u64>()
            .map_err(|_| "Неправильний коефіцієнт 'a': має бути додатнім цілим числом")?;

        // Parse gen_g_c
        self.params.gen_g_c = self
            .gen_g_c_str
            .parse::<u64>()
            .map_err(|_| "Неправильний коефіцієнт 'c': має бути додатнім цілим числом")?;

        // Parse gen_g_l
        self.params.gen_g_l = self
            .gen_g_l_str
            .parse::<u64>()
            .map_err(|_| "Неправильний параметр 'l': має бути додатнім цілим числом")?;

        // Parse gen_g_k
        self.params.gen_g_k = self
            .gen_g_k_str
            .parse::<u64>()
            .map_err(|_| "Неправильний порядок 'k': має бути додатнім цілим числом")?;

        // Parse gen_g_seed
        self.params.gen_g_seed = self
            .gen_g_seed_str
            .parse::<u64>()
            .map_err(|_| "Неправильна детермінована випадковість для Gen G: має бути додатнім цілим числом")?;

        // Parse equation_count
        self.params.equation_count = self
            .equation_count_str
            .parse::<usize>()
            .map_err(|_| "Неправильна кількість рівнянь: має бути додатнім цілим числом")?;

        // Parse variables_count
        self.params.variables_count = self
            .variables_count_str
            .parse::<usize>()
            .map_err(|_| "Неправильна кількість змінних: має бути додатнім цілим числом")?;

        // Basic validation
        if self.params.gen_g_a == 0 {
            return Err("Коефіцієнт 'a' має бути більше 0".to_string());
        }

        if self.params.gen_g_c == 0 {
            return Err("Коефіцієнт 'c' має бути більше 0".to_string());
        }

        if self.params.gen_g_l == 0 {
            return Err("Параметр 'l' має бути більше 0".to_string());
        }

        if self.params.gen_g_k == 0 {
            return Err("Порядок 'k' має бути більше 0".to_string());
        }

        if self.params.equation_count == 0 {
            return Err("Кількість рівнянь має бути більше 0".to_string());
        }

        if self.params.variables_count == 0 {
            return Err("Кількість змінних має бути більше 0".to_string());
        }

        if self.params.variables_count < self.params.equation_count {
            return Err("Кількість змінних має бути більше або дорівнювати кількості рівнянь".to_string());
        }

        // Advanced validations for Gen G algorithm requirements
        
        // Check reasonable bounds to prevent excessive computation
        if self.params.gen_g_k > 100_000 {
            return Err("Порядок 'k' занадто великий (максимум 100,000 для продуктивності)".to_string());
        }
        if self.params.gen_g_l > 10_000 {
            return Err("Параметр 'l' занадто великий (максимум 10,000 для продуктивності)".to_string());
        }
        if self.params.equation_count > 10 {
            return Err("Кількість рівнянь занадто велика (максимум 10 для продуктивності)".to_string());
        }
        if self.params.variables_count > 15 {
            return Err("Кількість змінних занадто велика (максимум 15 для продуктивності)".to_string());
        }

        // Check GCD constraints for both isomorphisms (required for gen_g)
        // First isomorphism uses modulus k
        let gcd_a_k = gcd(self.params.gen_g_a as i64, self.params.gen_g_k as i64);
        if gcd_a_k != 1 {
            return Err(format!(
                "НСД(a, k) має дорівнювати 1, але НСД({}, {}) = {}", 
                self.params.gen_g_a, 
                self.params.gen_g_k, 
                gcd_a_k
            ));
        }

        // Second isomorphism uses modulus m = k * l
        let modulus_m = self.params.gen_g_k * self.params.gen_g_l;
        let gcd_a_m = gcd(self.params.gen_g_a as i64, modulus_m as i64);
        if gcd_a_m != 1 {
            return Err(format!(
                "НСД(a, k*l) має дорівнювати 1, але НСД({}, {}) = {}", 
                self.params.gen_g_a, 
                modulus_m, 
                gcd_a_m
            ));
        }

        // Check for potential overflow in modulus_m calculation
        if self.params.gen_g_k > u64::MAX / self.params.gen_g_l {
            return Err("Параметри 'k' та 'l' занадто великі - їх добуток спричинить переповнення".to_string());
        }

        Ok(())
    }
}
