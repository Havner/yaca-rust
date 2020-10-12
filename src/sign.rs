use libc::{size_t, c_void, c_char};
use std::ptr;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::{Context, ContextWithPadding};
use crate::*;


/// Context for sign operations
pub struct SignContext {
    handle: *mut c_void,
}

impl Drop for SignContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle);
        };
    }
}

impl Context for SignContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for SignContext {}

impl SignContext {
    /// Initializes a signature context for asymmetric signatures.
    pub fn initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<SignContext>
    {
        sign_initialize(algo, prv_key)
    }
    /// Initializes a signature context for HMAC.
    pub fn initialize_hmac(algo: &DigestAlgorithm, sym_key: &Key) -> Result<SignContext>
    {
        sign_initialize_hmac(algo, sym_key)
    }
    /// Initializes a signature context for CMAC.
    pub fn initialize_cmac(algo: &EncryptAlgorithm, sym_key: &Key) -> Result<SignContext>
    {
        sign_initialize_cmac(algo, sym_key)
    }
    /// Feeds the message into the digital signature or MAC algorithm.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        sign_update(self, message)
    }
    /// Calculates the final signature or MAC.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        sign_finalize(self)
    }
}

/// Initializes a signature context for asymmetric signatures.
pub fn sign_initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<SignContext>
{
    let algo = conv::digest_rs_to_c(algo);
    let prv_key = key::get_handle(prv_key);
    let mut handle = ptr::null_mut() as *mut c_void;
    let r = unsafe {
        lib::yaca_sign_initialize(&mut handle, algo, prv_key)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(SignContext{handle})
}

/// Initializes a signature context for HMAC.
pub fn sign_initialize_hmac(algo: &DigestAlgorithm, sym_key: &Key) -> Result<SignContext>
{
    let algo = conv::digest_rs_to_c(algo);
    let sym_key = key::get_handle(sym_key);
    let mut handle = ptr::null_mut() as *mut c_void;
    let r = unsafe {
        lib::yaca_sign_initialize_hmac(&mut handle, algo, sym_key)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(SignContext{handle})
}

/// Initializes a signature context for CMAC.
pub fn sign_initialize_cmac(algo: &EncryptAlgorithm, sym_key: &Key) -> Result<SignContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let sym_key = key::get_handle(sym_key);
    let mut handle = ptr::null_mut() as *mut c_void;
    let r = unsafe {
        lib::yaca_sign_initialize_cmac(&mut handle, algo, sym_key)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(SignContext{handle})
}

/// Feeds the message into the digital signature or MAC algorithm.
pub fn sign_update(ctx: &SignContext, message: &[u8]) -> Result<()>
{
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_sign_update(ctx.handle, message, message_len)
    };
    conv::res_c_to_rs(r)
}

/// Calculates the final signature or MAC.
pub fn sign_finalize(ctx: &SignContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    assert!(output_len > 0);
    let mut digest_vec: Vec<u8> = Vec::with_capacity(output_len);
    let digest = digest_vec.as_mut_ptr() as *mut c_char;
    let mut digest_len: size_t = output_len;
    let r = unsafe {
        lib::yaca_sign_finalize(ctx.handle, digest, &mut digest_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(digest_len <= output_len);
    unsafe {
        digest_vec.set_len(digest_len as usize);
    };
    Ok(digest_vec)
}


/// Context for verify operations
pub struct VerifyContext {
    handle: *mut c_void,
}

impl Drop for VerifyContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle);
        };
    }
}

impl Context for VerifyContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for VerifyContext {}

impl VerifyContext {
    /// Initializes a signature verification context for asymmetric signatures.
    pub fn initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<VerifyContext>
    {
        verify_initialize(algo, prv_key)
    }
    /// Feeds the message into the digital signature verification algorithm.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        verify_update(self, message)
    }
    /// Performs the verification.
    pub fn finalize(&self, signature: &[u8]) -> Result<bool>
    {
        verify_finalize(self, signature)
    }
}

/// Initializes a signature verification context for asymmetric signatures.
pub fn verify_initialize(algo: &DigestAlgorithm, pub_key: &Key) -> Result<VerifyContext>
{
    let algo = conv::digest_rs_to_c(algo);
    let pub_key = key::get_handle(pub_key);
    let mut handle = ptr::null_mut() as *mut c_void;
    let r = unsafe {
        lib::yaca_verify_initialize(&mut handle, algo, pub_key)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(VerifyContext{handle})
}

/// Feeds the message into the digital signature verification algorithm.
pub fn verify_update(ctx: &VerifyContext, message: &[u8]) -> Result<()>
{
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_verify_update(ctx.handle, message, message_len)
    };
    conv::res_c_to_rs(r)
}

/// Performs the verification.
pub fn verify_finalize(ctx: &VerifyContext, signature: &[u8]) -> Result<bool>
{
    let signature_len: size_t = signature.len();
    let signature = signature.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_verify_finalize(ctx.handle, signature, signature_len)
    };
    conv::res_c_to_rs_bool(r)
}
