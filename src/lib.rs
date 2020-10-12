//! YACA - Yet Another Crypto API. Bindings for C library YACA
//!
//! Contains two APIs, one objectified a little. And one 1:1 with C
//! API. First one is available here, second one in module flat.


extern crate libc;


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
    pub use crate::crypto::ContextWithPadding;
    pub use crate::crypto::ContextWithRc2Supported;
    pub use crate::crypto::ContextWithXcmEncryptProperties;
    pub use crate::crypto::ContextWithXcmDecryptProperties;
}

// ******************************
// *   (mostly) objective API   *
// *    use yaca;               *
// *    use yaca::prelude::*;   *
// ******************************
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


/// Flat C-like alternative API. Functions are 1:1 from C API.
///
/// You can use it with:
///
///    use yaca::flat as yacaf
///
/// Everything you need is available under this module if you prefer
/// to use this API.
pub mod flat {
    // ****************************
    // *   flat API (like in C)   *
    // *  use yaca::flat as yacaf *
    // ****************************

    pub type Result<T> = std::result::Result<T, Error>;

    pub use crate::types::Error;
    pub use crate::types::KeyFormat;
    pub use crate::types::KeyFileFormat;
    pub use crate::types::KeyType;
    pub use crate::types::KeySubType::{self, *};
    pub use crate::types::KeyLength;
    pub use crate::types::KeyLengthEc::{self, *};
    pub use crate::types::KeyLengthDh::{self, *};
    pub use crate::types::DigestAlgorithm;
    pub use crate::types::EncryptAlgorithm;
    pub use crate::types::BlockCipherMode;
    pub use crate::types::Padding;
    pub use crate::types::Kdf;

    pub use crate::crypto::initialize;
    pub use crate::crypto::cleanup;
    pub use crate::crypto::memcmp;
    pub use crate::crypto::random_bytes;
    pub use crate::crypto::context_set_property_padding;
    pub use crate::crypto::context_set_property_gcm_aad;
    pub use crate::crypto::context_set_property_gcm_tag;
    pub use crate::crypto::context_set_property_gcm_tag_len;
    pub use crate::crypto::context_set_property_ccm_aad;
    pub use crate::crypto::context_set_property_ccm_tag;
    pub use crate::crypto::context_set_property_ccm_tag_len;
    pub use crate::crypto::context_set_property_rc2_effective_key_bits;
    pub use crate::crypto::context_get_property_gcm_tag;
    pub use crate::crypto::context_get_property_ccm_tag;

    pub use crate::simple::simple_encrypt;
    pub use crate::simple::simple_decrypt;
    pub use crate::simple::simple_calculate_digest;
    pub use crate::simple::simple_calculate_signature;
    pub use crate::simple::simple_verify_signature;
    pub use crate::simple::simple_calculate_cmac;
    pub use crate::simple::simple_calculate_hmac;

    pub use crate::rsa::rsa_public_encrypt;
    pub use crate::rsa::rsa_private_decrypt;
    pub use crate::rsa::rsa_private_encrypt;
    pub use crate::rsa::rsa_public_decrypt;

    pub use crate::key::key_get_type;
    pub use crate::key::key_get_length;
    pub use crate::key::key_import;
    pub use crate::key::key_export;
    pub use crate::key::key_generate;
    pub use crate::key::key_generate_from_parameters;
    pub use crate::key::key_extract_public;
    pub use crate::key::key_extract_parameters;
    pub use crate::key::key_derive_dh;
    pub use crate::key::key_derive_kdf;
    pub use crate::key::key_derive_pbkdf2;

    pub use crate::digest::digest_initialize;
    pub use crate::digest::digest_update;
    pub use crate::digest::digest_finalize;

    pub use crate::encrypt::encrypt_get_iv_length;
    pub use crate::encrypt::encrypt_initialize;
    pub use crate::encrypt::encrypt_set_input_length;
    pub use crate::encrypt::encrypt_update;
    pub use crate::encrypt::encrypt_finalize;
    pub use crate::encrypt::decrypt_initialize;
    pub use crate::encrypt::decrypt_set_input_length;
    pub use crate::encrypt::decrypt_update;
    pub use crate::encrypt::decrypt_finalize;

    pub use crate::seal::seal_initialize;
    pub use crate::seal::seal_set_input_length;
    pub use crate::seal::seal_update;
    pub use crate::seal::seal_finalize;
    pub use crate::seal::open_initialize;
    pub use crate::seal::open_set_input_length;
    pub use crate::seal::open_update;
    pub use crate::seal::open_finalize;

    pub use crate::sign::sign_initialize;
    pub use crate::sign::sign_initialize_hmac;
    pub use crate::sign::sign_initialize_cmac;
    pub use crate::sign::sign_update;
    pub use crate::sign::sign_finalize;
    pub use crate::sign::verify_initialize;
    pub use crate::sign::verify_update;
    pub use crate::sign::verify_finalize;
}
