//! Low-level RSA key pair (private key) API.

pub(crate) mod components;
pub(crate) mod core;
pub(crate) mod signing;

pub(in crate::rsa) use self::core::RsaKeyPair;
pub use components::Components;
