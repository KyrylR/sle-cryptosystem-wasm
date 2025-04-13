// A dependency graph that contains any wasm must all be imported
// asynchronously. This `bootstrap.js` file does the single async import, so
// that no one else needs to worry about it again.
console.log("Loading WASM module...");

async function run() {
    try {
        // Dynamically import the WASM package.
        // The './pkg' path assumes you run wasm-pack build and serve from the crypto-vis directory.
        const wasm = await import('./pkg/crypto_vis.js');

        // Initialize the WASM module. The default export is the init function.
        await wasm.default();

        console.log("WASM module loaded and initialized successfully.");

        // Hide loading message and show UI sections
        document.querySelector('p').style.display = 'none';
        document.getElementById('greeting').style.display = 'block';
        document.getElementById('ringCheck').style.display = 'block';

        // --- Greeting Example --- 
        const nameInput = document.getElementById('name');
        const greetButton = document.getElementById('greetButton');
        const greetResult = document.getElementById('greetResult');

        greetButton.addEventListener('click', () => {
            const name = nameInput.value;
            const result = wasm.greet(name); // Call the exported Rust function
            console.log("Greeting result:", result);
            greetResult.textContent = result;
        });

        // --- Ring Check Example --- 
        const modulusInput = document.getElementById('modulus');
        const checkRingButton = document.getElementById('checkRingButton');
        const ringResult = document.getElementById('ringResult');

        checkRingButton.addEventListener('click', () => {
            try {
                const modulus = BigInt(modulusInput.value); // Use BigInt for u64
                if (modulus <= 1n) {
                     ringResult.textContent = "Error: Modulus must be greater than 1.";
                     return;
                }
                const result = wasm.check_ring(modulus); // Call the exported Rust function
                console.log("Ring check result:", result);
                ringResult.textContent = result;
            } catch (e) {
                 console.error("Error calling check_ring:", e);
                 ringResult.textContent = `Error: ${e.message}`;
            }
        });

        // Initial calls on load (optional)
        greetButton.click();
        checkRingButton.click();

    } catch (error) {
        console.error("Error loading or initializing WASM module:", error);
        document.querySelector('p').textContent = 'Error loading WASM module. Check the console for details.';
    }
}

run(); 