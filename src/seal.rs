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


/// Context for `Seal` operations
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
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], plaintext_len: usize) -> Result<()>
    {
        seal_set_input_length(self, plaintext_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl SealContext {
    /// Initializes an asymmetric encryption context and generates
    /// symmetric key and Initialization Vector
    ///
    /// - `pub_key` is a key that the returned symmetric key will be
    ///   encrypted with, it must be of [`KeyType::RsaPublic`] type.
    /// - `algo` is an encryption algorithm used to encrypt the data.
    /// - `bcm` is a chaining used to encrypt the data.
    /// - `sym_key_length` defines the length of a generated symmetric
    ///   key, it must be at least 88 bits shorter than the `pub_key`
    ///   bit length.
    /// - The function returns a tupple of context, generated and
    ///   encrypted symmetric key and generated Initialization Vector
    ///   of the default length for a given encryption configuration
    ///   (or `None`).
    /// - The generated symmetric key is encrypted with public key, so
    ///   can be only used with [`OpenContext::initialize()`]. It can be
    ///   exported, but after import it can be only used with
    ///   [`OpenContext::initialize()`] as well.
    ///
    /// [`KeyType::RsaPublic`]: enum.KeyType.html#variant.RsaPublic
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    pub fn initialize(pub_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key_length: &KeyLength) -> Result<(SealContext, Key, Option<Key>)>
    {
        seal_initialize(pub_key, algo, bcm, sym_key_length)
    }
    /// Encrypts chunk of the data
    ///
    /// - `plaintext` is a chunk of data to be encrypted.
    /// - Returns a chunk of encrypted data.
    pub fn update(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    {
        seal_update(self, plaintext)
    }
    /// Encrypts the final chunk of the data
    ///
    /// - Returns the final chunk of encrypted data.
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
    debug_assert!(!sym_key.is_null());
    debug_assert!(!handle.is_null());
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
    let mut ciphertext_len = 0;
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
    debug_assert!(ciphertext_len <= output_len);
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
    debug_assert!(ciphertext_len <= output_len);
    unsafe {
        ciphertext_vec.set_len(ciphertext_len);
    };
    Ok(ciphertext_vec)
}

/// Context for `Open` operations
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
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], ciphertext_len: usize) -> Result<()>
    {
        open_set_input_length(self, ciphertext_len)?;
        crypto::context_set_property_multiple(self, types::Property::CcmAad, ccm_aad)
    }
}

impl OpenContext {
    /// Initializes an asymmetric decryption context
    ///
    /// - `prv_key` is a matching key to the public one that was used
    ///   in the encryption.
    /// - Other parameters passed must match the parameters used to encrypt the data.
    /// - See [`SealContext::initialize()`].
    ///
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    pub fn initialize(prv_key: &Key, algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                      sym_key_length: &KeyLength, sym_key: &Key,
                      iv: Option<&Key>) -> Result<OpenContext>
    {
        open_initialize(prv_key, algo, bcm, sym_key_length, sym_key, iv)
    }
    /// Decrypts chunk of the data.
    ///
    /// - `ciphertext` is a chunk of encrypted data to be decrypted.
    /// - Returns a chunk of decrypted data.
    pub fn update(&self, ciphertext: &[u8]) -> Result<Vec<u8>>
    {
        open_update(self, ciphertext)
    }
    /// Decrypts the final chunk of the data.
    ///
    /// - Returns the final chunk of decrypted data.
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
    debug_assert!(!handle.is_null());
    Ok(OpenContext{handle})
}

#[inline]
fn open_set_input_length(ctx: &OpenContext, input_len: usize) -> Result<()>
{
    let ctx = ctx.get_handle();
    let ciphertext = ptr::null();
    let ciphertext_len = input_len;
    let plaintext = ptr::null_mut();
    let mut plaintext_len = 0;
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
    debug_assert!(plaintext_len <= output_len);
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
    debug_assert!(plaintext_len <= output_len);
    unsafe {
        plaintext_vec.set_len(plaintext_len);
    };
    Ok(plaintext_vec)
}
