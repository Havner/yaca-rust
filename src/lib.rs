//! YACA - Yet Another Crypto API. Bindings for C library YACA
//!
//! use yaca::{self, prelude::*}

mod yaca_lib;
mod yaca_conv;

mod types;
mod crypto;
mod simple;
mod rsa;
mod key;
mod digest;
mod encrypt;
mod seal;
mod sign;


pub mod prelude {
    pub use super::crypto::ContextWithPadding;
    pub use super::crypto::ContextWithRc2Supported;
    pub use super::crypto::ContextWithXcmEncryptProperties;
    pub use super::crypto::ContextWithXcmDecryptProperties;
}

// TODO: consider simplifying those pub use in the future

pub type Result<T> = std::result::Result<T, Error>;

pub use prelude::*;

pub use types::Error;
pub use types::KeyFormat;
pub use types::KeyFileFormat;
pub use types::KeyType;
pub use types::KeySubType::{self, *};
pub use types::KeyLength;
pub use types::KeyLengthEc::{self, *};
pub use types::KeyLengthDh::{self, *};
pub use types::DigestAlgorithm;
pub use types::EncryptAlgorithm;
pub use types::BlockCipherMode;
pub use types::Padding;
pub use types::Kdf;

pub use crypto::initialize;
pub use crypto::cleanup;
pub use crypto::memcmp;
pub use crypto::random_bytes;

pub use simple::simple_encrypt;
pub use simple::simple_decrypt;
pub use simple::simple_calculate_digest;
pub use simple::simple_calculate_signature;
pub use simple::simple_verify_signature;
pub use simple::simple_calculate_cmac;
pub use simple::simple_calculate_hmac;

pub use rsa::rsa_public_encrypt;
pub use rsa::rsa_private_decrypt;
pub use rsa::rsa_private_encrypt;
pub use rsa::rsa_public_decrypt;

pub use key::Key;
pub use digest::DigestContext;
pub use encrypt::EncryptContext;
pub use encrypt::DecryptContext;
pub use seal::SealContext;
pub use seal::OpenContext;
pub use sign::SignContext;
pub use sign::VerifyContext;
