use libc::{c_void, c_char};
use std::ptr;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::Context;
use crate::*;


/// Context for digest operations
pub struct DigestContext {
    handle: *mut c_void,
}

impl Drop for DigestContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
    }
}

impl Context for DigestContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl DigestContext {
    /// Initializes a digest context.
    pub fn initialize(algo: &DigestAlgorithm) -> Result<DigestContext>
    {
        digest_initialize(algo)
    }
    /// Feeds the message into the message digest algorithm.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        digest_update(self, message)
    }
    /// Calculates the final digest.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        digest_finalize(&self)
    }
}


#[inline]
fn digest_initialize(algo: &DigestAlgorithm) -> Result<DigestContext>
{
    let algo = conv::digest_rs_to_c(algo);
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_digest_initialize(&mut handle, algo)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(DigestContext{handle})
}

#[inline]
fn digest_update(ctx: &DigestContext, message: &[u8]) -> Result<()>
{
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_digest_update(ctx.handle, message, message_len)
    };
    conv::res_c_to_rs(r)
}

#[inline]
fn digest_finalize(ctx: &DigestContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    assert!(output_len > 0);
    let mut digest_vec: Vec<u8> = Vec::with_capacity(output_len);
    let digest = digest_vec.as_mut_ptr() as *mut c_char;
    let mut digest_len = output_len;
    let r = unsafe {
        lib::yaca_digest_finalize(ctx.handle, digest, &mut digest_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(digest_len <= output_len);
    unsafe {
        digest_vec.set_len(digest_len);
    };
    Ok(digest_vec)
}
