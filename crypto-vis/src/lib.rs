use crypto::ring::Ring;
use wasm_bindgen::prelude::*;
use web_sys::console;

// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Called once when the wasm module is instantiated.
/// Use this function to set up global state or perform initializations.
#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // This provides better error messages in debug mode.
    // It's disabled in release mode so it doesn't bloat up the file size.
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    console::log_1(&"WASM module initialized.".into());

    Ok(())
}

/// An example function that can be called from JavaScript.
#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    console::log_1(&format!("Greeting {} from Rust!", name).into());
    format!("Hello, {}!", name)
}

/// Example using the crypto library
#[wasm_bindgen]
pub fn check_ring(modulus: u64) -> String {
    match Ring::try_with(modulus) {
        Ok(ring) => format!(
            "Successfully created Ring with modulus {}. Normalized 5: {}",
            modulus,
            ring.normalize(5)
        ),
        Err(e) => format!("Failed to create Ring with modulus {}: {:?}", modulus, e),
    }
}
