use libc::{size_t, c_void, c_char};
use std::ptr;
use std::mem;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::{Context, ContextWithPadding, ContextWithRc2Supported,
                    ContextWithXcmEncryptProperties, ContextWithXcmDecryptProperties};
use crate::*;


/// Context for encrypt operations
pub struct EncryptContext {
    handle: *mut c_void,
}

impl Drop for EncryptContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle);
        };
    }
}

impl Context for EncryptContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for EncryptContext {}
impl ContextWithRc2Supported for EncryptContext {}
impl ContextWithXcmEncryptProperties for EncryptContext {}

impl EncryptContext {
    /// Returns the recommended/default length of the Initialization Vector
    /// for a given encryption configuration.
    pub fn get_iv_length(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                         key_length: &KeyLength) -> Result<Option<KeyLength>>
    {
        encrypt_get_iv_length(algo, bcm, key_length)
    }
    /// Initializes an encryption context.
    pub fn initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<EncryptContext>
    {
        encrypt_initialize(algo, bcm, sym_key, iv)
    }
    /// Sets the total length of the input. This is only used for CCM_AAD.
    /// TODO: Consider dropping the flat API. Then all 4 "set_input_length" methods
    /// can be merged with "set_property_ccm_add(aad, input_len)"
    pub fn set_input_length(&self, input_len: usize) -> Result<()>
    {
        encrypt_set_input_length(self, input_len)
    }
    /// Encrypts chunk of the data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        encrypt_update(self, plaintext)
    }
    /// Encrypts the final chunk of the data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        encrypt_finalize(&self)
    }
}

/// Returns the recommended/default length of the Initialization Vector
/// for a given encryption configuration.
pub fn encrypt_get_iv_length(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                             key_length: &KeyLength) -> Result<Option<KeyLength>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let key_bit_len = conv::key_length_rs_to_c(key_length);
    let mut iv_bit_len: size_t = 0;
    let r = unsafe {
        lib::yaca_encrypt_get_iv_bit_length(algo, bcm, key_bit_len, &mut iv_bit_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(iv_bit_len <= std::u16::MAX as usize);
    match iv_bit_len {
        0 => Ok(None),
        x => Ok(Some(KeyLength::Bits(x as u16))),
    }
}

/// Initializes an encryption context.
pub fn encrypt_initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                          sym_key: &Key, iv: Option<&Key>) -> Result<EncryptContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let mut handle: *mut c_void = ptr::null_mut();
    let r = unsafe {
        lib::yaca_encrypt_initialize(&mut handle, algo, bcm, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(EncryptContext{handle})
}

/// Sets the total length of the input. This is only used for CCM_AAD.
pub fn encrypt_set_input_length(ctx: &EncryptContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let plaintext = ptr::null() as *const c_char;
    let plaintext_len = input_len as size_t;
    let ciphertext = ptr::null_mut() as *mut c_char;
    let mut ciphertext_len: size_t = mem::size_of::<size_t>();
    let r = unsafe {
        lib::yaca_encrypt_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(())
}

/// Encrypts chunk of the data.
pub fn encrypt_update(ctx: &EncryptContext, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let plaintext_len = plaintext.len();
    let output_len = ctx.get_output_length(plaintext_len)?;
    let ctx = ctx.handle;
    let plaintext = match plaintext_len {
        0 => ptr::null(),
        _ => plaintext.as_ptr() as *const c_char,
    };
    let mut ciphertext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut ciphertext_len: size_t = 0;
    let ciphertext = ciphertext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_encrypt_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len as usize);
    };
    Ok(ciphertext_vec)
}

/// Encrypts the final chunk of the data.
pub fn encrypt_finalize(ctx: &EncryptContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut ciphertext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut ciphertext_len: size_t = 0;
    let ciphertext = ciphertext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_encrypt_finalize(ctx, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len as usize);
    };
    Ok(ciphertext_vec)
}

/// Context for decrypt operations
pub struct DecryptContext {
    handle: *mut c_void,
}

impl Drop for DecryptContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle);
        };
    }
}

impl Context for DecryptContext {
    fn get_handle(&self) -> *mut c_void
    {
        self.handle
    }
}

impl ContextWithPadding for DecryptContext {}
impl ContextWithRc2Supported for DecryptContext {}
impl ContextWithXcmDecryptProperties for DecryptContext {}

impl DecryptContext {
    /// Initializes an decryption context.
    pub fn initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<DecryptContext>
    {
        decrypt_initialize(algo, bcm, sym_key, iv)
    }
    /// Sets the total length of the input. This is only used for CCM_AAD.
    pub fn set_input_length(&self, input_len: usize) -> Result<()>
    {
        decrypt_set_input_length(self, input_len)
    }
    /// Decrypts chunk of the data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        decrypt_update(self, plaintext)
    }
    /// Decrypts the final chunk of the data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        decrypt_finalize(&self)
    }
}

/// Initializes an encryption context.
pub fn decrypt_initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                          sym_key: &Key, iv: Option<&Key>) -> Result<DecryptContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let mut handle: *mut c_void = ptr::null_mut();
    let r = unsafe {
        lib::yaca_decrypt_initialize(&mut handle, algo, bcm, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(DecryptContext{handle})
}

/// Sets the total length of the input. This is only used for CCM_AAD.
pub fn decrypt_set_input_length(ctx: &DecryptContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let ciphertext = ptr::null() as *const c_char;
    let ciphertext_len = input_len as size_t;
    let plaintext = ptr::null_mut() as *mut c_char;
    let mut plaintext_len: size_t = mem::size_of::<size_t>();
    let r = unsafe {
        lib::yaca_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(())
}

/// Encrypts chunk of the data.
pub fn decrypt_update(ctx: &DecryptContext, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let ciphertext_len = ciphertext.len();
    let output_len = ctx.get_output_length(ciphertext_len)?;
    let ctx = ctx.handle;
    let ciphertext = match ciphertext_len {
        0 => ptr::null(),
        _ => ciphertext.as_ptr() as *const c_char,
    };
    let mut plaintext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut plaintext_len: size_t = 0;
    let plaintext = plaintext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len as usize);
    };
    Ok(plaintext_vec)
}

/// Encrypts the final chunk of the data.
pub fn decrypt_finalize(ctx: &DecryptContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut plaintext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut plaintext_len: size_t = 0;
    let plaintext = plaintext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_decrypt_finalize(ctx, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len as usize);
    };
    Ok(plaintext_vec)
}
