use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    /// A static HashMap mapping an index (0 to 64) to its corresponding
    /// standard Base64 character (A-Z, a-z, 0-9, +, /, =).
    pub static ref INDEX_TO_BASE64_CHAR_MAP: HashMap<u8, char> = {
        let mut map = HashMap::new();
        let base64_chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".chars().collect();

        // Map indices 1 through 64 to the characters at index 0 through 64
        for i in 0..=64 {
            if let Some(ch) = base64_chars.get(i as usize) {
                map.insert(i as u8, *ch);
            }
        }

        map
    };

    /// A static HashMap mapping a Base64 character (A-Z, a-z, 0-9, +, /, =) to its
    /// corresponding index (0 to 64).
    pub static ref BASE64_CHAR_TO_INDEX_MAP: HashMap<char, u8> = {
        let mut map = HashMap::new();

        for (&index, &ch) in INDEX_TO_BASE64_CHAR_MAP.iter() {
            map.insert(ch, index);
        }

        map
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use quickcheck::TestResult;
    use quickcheck::quickcheck;

    use std::collections::HashMap;

    const BASE64_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    quickcheck! {
        fn prop_base64_encode_matches_map(data: Vec<u8>) -> TestResult {
            let encoded = STANDARD.encode(&data);
            let reverse_map: HashMap<char, u8> = INDEX_TO_BASE64_CHAR_MAP
                .iter()
                .map(|(&k, &v)| (v, k))
                .collect();

            for char_in_encoded in encoded.chars() {
                let expected_index_opt = BASE64_CHARS.find(char_in_encoded).map(|pos| pos as u8);

                if let Some(expected_index) = expected_index_opt {
                    // Look up the character in our reverse map
                    if let Some(map_index) = reverse_map.get(&char_in_encoded) {
                        if *map_index != expected_index {
                            // Mismatch between map index and expected index
                            return TestResult::error(format!(
                                "Mismatch for char '{}': Expected index {}, found index {} in map",
                                char_in_encoded,
                                expected_index,
                                map_index
                            ));
                        }
                    } else {
                        // Character found in standard alphabet but not in our map's values
                        return TestResult::error(format!(
                            "Character '{}' from Base64 encoding not found as a value in INDEX_TO_BASE64_CHAR_MAP",
                            char_in_encoded
                        ));
                    }
                } else {
                    // Character from Base64 encoding is not in the standard alphabet - this shouldn't happen with STANDARD encoding
                    return TestResult::error(format!(
                        "Character '{}' from Base64 encoding not found in standard BASE64_CHARS constant",
                        char_in_encoded
                    ));
                }
            }

            TestResult::passed()
        }
    }
}
