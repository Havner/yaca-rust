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

use libc::c_void;

use crate::yaca_common as common;
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
    let handle = common::enc_init(algo, bcm, sym_key, iv, lib::yaca_encrypt_initialize)?;
    Ok(EncryptContext{handle})
}

#[inline]
fn encrypt_set_input_length(ctx: &EncryptContext, input_len: usize) -> Result<()>
{
    common::enc_set_input_length(ctx, input_len, lib::yaca_encrypt_update)
}

#[inline]
fn encrypt_update(ctx: &EncryptContext, plaintext: &[u8]) -> Result<Vec<u8>>
{
    common::enc_upd(ctx, plaintext, lib::yaca_encrypt_update)
}

#[inline]
fn encrypt_finalize(ctx: &EncryptContext) -> Result<Vec<u8>>
{
    common::enc_fin(ctx, lib::yaca_encrypt_finalize)
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
    let handle = common::enc_init(algo, bcm, sym_key, iv, lib::yaca_decrypt_initialize)?;
    Ok(DecryptContext{handle})
}

#[inline]
fn decrypt_set_input_length(ctx: &DecryptContext, input_len: usize) -> Result<()>
{
    common::enc_set_input_length(ctx, input_len, lib::yaca_decrypt_update)
}

#[inline]
fn decrypt_update(ctx: &DecryptContext, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    common::enc_upd(ctx, ciphertext, lib::yaca_decrypt_update)
}

#[inline]
fn decrypt_finalize(ctx: &DecryptContext) -> Result<Vec<u8>>
{
    common::enc_fin(ctx, lib::yaca_decrypt_finalize)
}
