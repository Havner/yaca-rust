/*
 *  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

use libc::{c_void, c_char};
use std::ptr;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::{Context, ContextWithPadding, ContextWithRc2Supported,
                    ContextWithXcmEncryptProperties, ContextWithXcmDecryptProperties};
use crate::*;


/// Context for `Encrypt` operations
pub struct EncryptContext {
    handle: *mut c_void,
}

impl Drop for EncryptContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
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
impl ContextWithXcmEncryptProperties for EncryptContext {
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], plaintext_len: usize) -> Result<()>
    {
        encrypt_set_input_length(self, plaintext_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl EncryptContext {
    /// Returns the recommended/default length of the Initialization Vector
    /// for a given encryption configuration
    ///
    ///  - If `None` returned that means that for this specific
    ///    algorithm and its parameters Initialization Vector is not
    ///    used.
    pub fn get_iv_length(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                         key_length: &KeyLength) -> Result<Option<KeyLength>>
    {
        encrypt_get_iv_length(algo, bcm, key_length)
    }
    /// Initializes an encryption context
    ///
    /// - `algo` is an encryption algorithm used to encrypt the data.
    /// - `bcm` is a chaining mode used to encrypt the data.
    /// - `sym_key` is a symmetric key used to encrypt the data.
    /// - `iv` is an optional Initialization Vector used to encrypt
    ///   the data, see [`EncryptContext::get_iv_length()`]
    ///
    /// [`EncryptContext::get_iv_length()`]: struct.EncryptContext.html#method.get_iv_length
    pub fn initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<EncryptContext>
    {
        encrypt_initialize(algo, bcm, sym_key, iv)
    }
    /// Encrypts chunk of the data
    ///
    /// - `plaintext` is a chunk of data to be encrypted.
    /// - Returns a chunk of encrypted data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        encrypt_update(self, plaintext)
    }
    /// Encrypts the final chunk of the data
    ///
    /// - Returns the final chunk of encrypted data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        encrypt_finalize(&self)
    }
}

#[inline]
fn encrypt_get_iv_length(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                         key_length: &KeyLength) -> Result<Option<KeyLength>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let key_bit_len = conv::key_length_rs_to_c(key_length);
    let mut iv_bit_len = 0;
    let r = unsafe {
        lib::yaca_encrypt_get_iv_bit_length(algo, bcm, key_bit_len, &mut iv_bit_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(iv_bit_len <= std::u16::MAX as usize);
    match iv_bit_len {
        0 => Ok(None),
        x => Ok(Some(KeyLength::Bits(x as u16))),
    }
}

#[inline]
fn encrypt_initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<EncryptContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_encrypt_initialize(&mut handle, algo, bcm, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(EncryptContext{handle})
}

#[inline]
fn encrypt_set_input_length(ctx: &EncryptContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let plaintext = ptr::null();
    let plaintext_len = input_len;
    let ciphertext = ptr::null_mut();
    let mut ciphertext_len = 0;
    let r = unsafe {
        lib::yaca_encrypt_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)
}

#[inline]
fn encrypt_update(ctx: &EncryptContext, plaintext: &[u8]) -> Result<Vec<u8>>
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
        lib::yaca_encrypt_update(ctx, plaintext, plaintext_len, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len);
    };
    Ok(ciphertext_vec)
}

#[inline]
fn encrypt_finalize(ctx: &EncryptContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut ciphertext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut ciphertext_len = 0;
    let ciphertext = ciphertext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_encrypt_finalize(ctx, ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len);
    };
    Ok(ciphertext_vec)
}

/// Context for `Decrypt` operations
pub struct DecryptContext {
    handle: *mut c_void,
}

impl Drop for DecryptContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
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
impl ContextWithXcmDecryptProperties for DecryptContext {
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], ciphertext_len: usize) -> Result<()>
    {
        decrypt_set_input_length(self, ciphertext_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl DecryptContext {
    /// Initializes a decryption context
    ///
    /// - Parameters passed must match the parameters used to encrypt the data.
    /// - See [`EncryptContext::initialize()`]
    ///
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    pub fn initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<DecryptContext>
    {
        decrypt_initialize(algo, bcm, sym_key, iv)
    }
    /// Decrypts chunk of the data
    ///
    /// - `ciphertext` is a chunk of encrypted data to be decrypted.
    /// - Returns a chunk of decrypted data.
    pub fn update(&self, ciphertext: &[u8]) -> Result<Vec<u8>>
    {
        decrypt_update(self, ciphertext)
    }
    /// Decrypts the final chunk of the data
    ///
    /// - Returns the final chunk of decrypted data.
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        decrypt_finalize(&self)
    }
}


#[inline]
fn decrypt_initialize(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key: &Key, iv: Option<&Key>) -> Result<DecryptContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_decrypt_initialize(&mut handle, algo, bcm, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(DecryptContext{handle})
}

#[inline]
fn decrypt_set_input_length(ctx: &DecryptContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let ciphertext = ptr::null();
    let ciphertext_len = input_len;
    let plaintext = ptr::null_mut();
    let mut plaintext_len = 0;
    let r = unsafe {
        lib::yaca_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)
}

#[inline]
fn decrypt_update(ctx: &DecryptContext, ciphertext: &[u8]) -> Result<Vec<u8>>
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
        lib::yaca_decrypt_update(ctx, ciphertext, ciphertext_len, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len);
    };
    Ok(plaintext_vec)
}

#[inline]
fn decrypt_finalize(ctx: &DecryptContext) -> Result<Vec<u8>>
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.handle;
    let mut plaintext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut plaintext_len = 0;
    let plaintext = plaintext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_decrypt_finalize(ctx, plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len);
    };
    Ok(plaintext_vec)
}
