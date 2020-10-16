use libc::{size_t, c_void, c_char};
use std::ptr;
use std::mem;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::{Context, ContextWithPadding, ContextWithRc2Supported,
                    ContextWithXcmEncryptProperties, ContextWithXcmDecryptProperties};
use crate::*;


/// Context for seal operations
pub struct SealContext {
    handle: *mut c_void,
}

impl Drop for SealContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
    }
}

impl Context for SealContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for SealContext {}
impl ContextWithRc2Supported for SealContext {}
impl ContextWithXcmEncryptProperties for SealContext {
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], input_len: usize) -> Result<()>
    {
        seal_set_input_length(self, input_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl SealContext {
    /// Initializes an encryption context.
    pub fn initialize(pub_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key_length: &KeyLength) -> Result<(SealContext, Key, Option<Key>)>
    {
        seal_initialize(pub_key, algo, bcm, sym_key_length)
    }
    /// Encrypts chunk of the data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        seal_update(self, plaintext)
    }
    /// Encrypts the final chunk of the data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        seal_finalize(&self)
    }
}

#[inline]
fn seal_initialize(pub_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                   sym_key_length: &KeyLength) -> Result<(SealContext, Key, Option<Key>)>
{
    let pub_key = key::get_handle(&pub_key);
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key_bit_length = conv::key_length_rs_to_c(sym_key_length);
    let mut sym_key = ptr::null();
    let mut iv = ptr::null();
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_seal_initialize(&mut handle, pub_key, algo, bcm, sym_key_bit_length,
                                  &mut sym_key, &mut iv)
    };
    conv::res_c_to_rs(r)?;
    assert!(!sym_key.is_null());
    assert!(!handle.is_null());
    let iv = if !iv.is_null() {
        Some(key::new_key(iv))
    } else {
        None
    };
    let sym_key = key::new_key(sym_key);
    let ctx = SealContext{handle};
    Ok((ctx, sym_key, iv))
}

#[inline]
fn seal_set_input_length(ctx: &SealContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let plaintext = ptr::null();
    let plaintext_len = input_len;
    let ciphertext = ptr::null_mut();
    let mut ciphertext_len = mem::size_of::<size_t>();
    let r = unsafe {
        lib::yaca_seal_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)
}

#[inline]
fn seal_update(ctx: &SealContext, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let plaintext_len = plaintext.len();
    let output_len = ctx.get_output_length(plaintext_len)?;
    let ctx = ctx.handle;
    let plaintext = match plaintext_len {
        0 => ptr::null(),
        _ => plaintext.as_ptr() as *const c_char,
    };
    let mut ciphertext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut ciphertext_len = 0;
    let ciphertext = ciphertext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_seal_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len);
    };
    Ok(ciphertext_vec)
}

#[inline]
fn seal_finalize(ctx: &SealContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut ciphertext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut ciphertext_len = 0;
    let ciphertext = ciphertext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_seal_finalize(ctx, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len);
    };
    Ok(ciphertext_vec)
}

/// Context for open operations
pub struct OpenContext {
    handle: *mut c_void,
}

impl Drop for OpenContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
    }
}

impl Context for OpenContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for OpenContext {}
impl ContextWithRc2Supported for OpenContext {}
impl ContextWithXcmDecryptProperties for OpenContext {
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], input_len: usize) -> Result<()>
    {
        open_set_input_length(self, input_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl OpenContext {
    /// Initializes an decryption context.
    pub fn initialize(prv_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key_length: &KeyLength, sym_key: &Key,
                      iv: Option<&Key>) -> Result<OpenContext>
    {
        open_initialize(prv_key, algo, bcm, sym_key_length, sym_key, iv)
    }
    /// Decrypts chunk of the data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        open_update(self, plaintext)
    }
    /// Decrypts the final chunk of the data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        open_finalize(&self)
    }
}

#[inline]
fn open_initialize(prv_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                   sym_key_length: &KeyLength, sym_key: &Key,
                   iv: Option<&Key>) -> Result<OpenContext>
{
    let prv_key = key::get_handle(&prv_key);
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key_bit_len = conv::key_length_rs_to_c(&sym_key_length);
    let sym_key = key::get_handle(sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_open_initialize(&mut handle, prv_key, algo, bcm,
                                  sym_key_bit_len, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(OpenContext{handle})
}

#[inline]
fn open_set_input_length(ctx: &OpenContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let ciphertext = ptr::null();
    let ciphertext_len = input_len;
    let plaintext = ptr::null_mut();
    let mut plaintext_len = mem::size_of::<size_t>();
    let r = unsafe {
        lib::yaca_open_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)
}

#[inline]
fn open_update(ctx: &OpenContext, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let ciphertext_len = ciphertext.len();
    let output_len = ctx.get_output_length(ciphertext_len)?;
    let ctx = ctx.handle;
    let ciphertext = match ciphertext_len {
        0 => ptr::null(),
        _ => ciphertext.as_ptr() as *const c_char,
    };
    let mut plaintext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut plaintext_len = 0;
    let plaintext = plaintext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_open_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len);
    };
    Ok(plaintext_vec)
}

#[inline]
fn open_finalize(ctx: &OpenContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut plaintext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut plaintext_len = 0;
    let plaintext = plaintext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_open_finalize(ctx, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len);
    };
    Ok(plaintext_vec)
}
