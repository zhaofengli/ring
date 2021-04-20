mod digest_scalar;
#[cfg(not(target_arch = "wasm32"))]
pub mod signing;
pub mod verification;
