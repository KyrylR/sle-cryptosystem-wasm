#![allow(non_snake_case)]

pub mod errors;
pub mod gen_g;
pub mod keypair;
pub mod preset;
pub mod ring;
pub mod sle;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
