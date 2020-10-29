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

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::{Context, ContextWithPadding};
use crate::*;


/// Context for `Sign` operations
pub struct SignContext {
    handle: *mut c_void,
}

impl Drop for SignContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
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
    /// Initializes a signature context for asymmetric signatures
    ///
    /// - `algo` is a digest algorithm that will be used.
    /// - `prv_key` is a private key that will be used, algorithm is
    ///   deduced based on key type, supported key types:
    ///   * [`KeyType::RsaPrivate`],
    ///   * [`KeyType::DsaPrivate`],
    ///   * [`KeyType::EcPrivate`].
    /// - For verification use [`VerifyContext`] with matching public key.
    /// - For RSA operations the default padding used is [`Padding::Pkcs1`]. It can be
    ///   changed using [`CtxPad::set_property_padding()`].
    /// - For [`DigestAlgorithm::Sha384`] and
    ///   [`DigestAlgorithm::Sha512`] the `RSA` key size must be bigger
    ///   than 512 bits.
    /// - Using [`DigestAlgorithm::Md5`] algorithm for `DSA` and
    ///   `ECDSA` operations is prohibited.
    /// - Using [`DigestAlgorithm::Md5`] or
    ///   [`DigestAlgorithm::Sha224`] with [`Padding::X931`] is
    ///   prohibited.
    ///
    /// [`KeyType::RsaPrivate`]: enum.KeyType.html#variant.RsaPrivate
    /// [`KeyType::DsaPrivate`]: enum.KeyType.html#variant.DsaPrivate
    /// [`KeyType::EcPrivate`]: enum.KeyType.html#variant.EcPrivate
    /// [`VerifyContext`]: struct.VerifyContext.html
    /// [`Padding::Pkcs1`]: enum.Padding.html#variant.Pkcs1
    /// [`CtxPad::set_property_padding()`]: trait.ContextWithPadding.html#method.set_property_padding
    /// [`DigestAlgorithm::Sha384`]: enum.DigestAlgorithm.html#variant.Sha384
    /// [`DigestAlgorithm::Sha512`]: enum.DigestAlgorithm.html#variant.Sha512
    /// [`DigestAlgorithm::Md5`]: enum.DigestAlgorithm.html#variant.Md5
    /// [`DigestAlgorithm::Sha224`]: enum.DigestAlgorithm.html#variant.Sha224
    /// [`Padding::X931`]: enum.Padding.html#variant.X931
    pub fn initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<SignContext>
    {
        sign_initialize(algo, prv_key)
    }
    /// Initializes a signature context for HMAC
    ///
    /// - `algo` is a digest algorithm that will be used.
    /// - `sym_key` is a key that will be used, supported key types:
    ///   * [`KeyType::Symmetric`],
    ///   * [`KeyType::Des`].
    /// - For verification, calculate message HMAC and compare with
    ///   received MAC using [`Yaca::memcmp()`].
    ///
    /// [`KeyType::Symmetric`]: enum.KeyType.html#variant.Symmetric
    /// [`KeyType::Des`]: enum.KeyType.html#variant.Des
    /// [`Yaca::memcmp()`]: fn.memcmp.html
    pub fn initialize_hmac(algo: &DigestAlgorithm, sym_key: &Key) -> Result<SignContext>
    {
        sign_initialize_hmac(algo, sym_key)
    }
    /// Initializes a signature context for CMAC
    ///
    /// - `algo` is an encryption algorithm that will be used.
    /// - `sym_key` is a key that will be used, supported key types:
    ///   * [`KeyType::Symmetric`],
    ///   * [`KeyType::Des`].
    /// - For verification, calculate message CMAC and compare with
    ///   received MAC using [`Yaca::memcmp()`].
    ///
    /// [`KeyType::Symmetric`]: enum.KeyType.html#variant.Symmetric
    /// [`KeyType::Des`]: enum.KeyType.html#variant.Des
    /// [`Yaca::memcmp()`]: fn.memcmp.html
    pub fn initialize_cmac(algo: &EncryptAlgorithm, sym_key: &Key) -> Result<SignContext>
    {
        sign_initialize_cmac(algo, sym_key)
    }
    /// Feeds the message into the digital signature or MAC algorithm
    ///
    /// - `message` is a chunk of data to calculate signature or MAC from.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        sign_update(self, message)
    }
    /// Calculates the final signature or MAC
    ///
    /// - Returns the calculated signature or MAC.
    /// - Skipping [`SignContext::update()`] and calling only
    ///   `SignContext::finalize()` will produce a signature or MAC of
    ///   an empty message.
    ///
    /// [`SignContext::update()`]: struct.SignContext.html#method.update
    pub fn finalize(&self) -> Result<Vec<u8>>
    {
        sign_finalize(self)
    }
}

#[inline]
fn sign_initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<SignContext>
{
    let handle = common::sign_init(algo, prv_key, lib::yaca_sign_initialize)?;
    Ok(SignContext{handle})
}

#[inline]
fn sign_initialize_hmac(algo: &DigestAlgorithm, sym_key: &Key) -> Result<SignContext>
{
    let handle = common::sign_init(algo, sym_key, lib::yaca_sign_initialize_hmac)?;
    Ok(SignContext{handle})
}

#[inline]
fn sign_initialize_cmac(algo: &EncryptAlgorithm, sym_key: &Key) -> Result<SignContext>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let sym_key = key::get_handle(sym_key);
    let mut handle = ptr::null_mut();
    let r = unsafe {
        lib::yaca_sign_initialize_cmac(&mut handle, algo, sym_key)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(SignContext{handle})
}

#[inline]
fn sign_update(ctx: &SignContext, message: &[u8]) -> Result<()>
{
    common::hash_upd(ctx, message, lib::yaca_sign_update)
}

#[inline]
fn sign_finalize(ctx: &SignContext) -> Result<Vec<u8>>
{
    common::hash_fin(ctx, lib::yaca_sign_finalize)
}


/// Context for `Verify` operations
pub struct VerifyContext {
    handle: *mut c_void,
}

impl Drop for VerifyContext {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_context_destroy(self.handle)
        }
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
    /// Initializes a signature verification context for asymmetric signatures
    ///
    /// - `algo` is a digest algorithm used to calculate the signature
    /// - `pub_key` is a matching public key to the one used to
    ///   calculate the signature, algorithm is deduced based on key
    ///   type, supported key types:
    ///   * [`KeyType::RsaPublic`],
    ///   * [`KeyType::DsaPublic`],
    ///   * [`KeyType::EcPublic`].
    /// - For RSA operations the default padding used
    ///   is [`Padding::Pkcs1`]. It can be changed using
    ///   [`CtxPad::set_property_padding()`]. For verify to succeed
    ///   it has to be set to the same value it was signed with.
    ///
    /// [`KeyType::RsaPublic`]: enum.KeyType.html#variant.RsaPublic
    /// [`KeyType::DsaPublic`]: enum.KeyType.html#variant.DsaPublic
    /// [`KeyType::EcPublic`]: enum.KeyType.html#variant.EcPublic
    /// [`Padding::Pkcs1`]: enum.Padding.html#variant.Pkcs1
    /// [`CtxPad::set_property_padding()`]: trait.ContextWithPadding.html#method.set_property_padding
    pub fn initialize(algo: &DigestAlgorithm, prv_key: &Key) -> Result<VerifyContext>
    {
        verify_initialize(algo, prv_key)
    }
    /// Feeds the message into the digital signature verification algorithm
    ///
    /// - `message` is a chunk of data used to calculate the signature from.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        verify_update(self, message)
    }
    /// Performs the verification
    ///
    /// - `signature` is a message signature to be verified.
    /// - Returns `true` in case of a successful verification,
    ///   `false` otherwise.
    pub fn finalize(&self, signature: &[u8]) -> Result<bool>
    {
        verify_finalize(self, signature)
    }
}

#[inline]
fn verify_initialize(algo: &DigestAlgorithm, pub_key: &Key) -> Result<VerifyContext>
{
    let handle = common::sign_init(algo, pub_key, lib::yaca_verify_initialize)?;
    Ok(VerifyContext{handle})
}

#[inline]
fn verify_update(ctx: &VerifyContext, message: &[u8]) -> Result<()>
{
    common::hash_upd(ctx, message, lib::yaca_verify_update)
}

#[inline]
fn verify_finalize(ctx: &VerifyContext, signature: &[u8]) -> Result<bool>
{
    let signature_len = signature.len();
    let signature = signature.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_verify_finalize(ctx.handle, signature, signature_len)
    };
    conv::res_c_to_rs_bool(r)
}
