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

use libc::{c_char, c_void};
use num_integer::Integer;
use std::mem;
use std::ptr;
use std::cmp;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


// Base trait for different contexts, not exported outside the crate.
// Cannot be pub(crate) as it's used by other Contexts that are exported.
pub trait Context {
    fn get_handle(&self) -> *mut c_void;
    fn get_output_length(&self, input_len: usize) -> Result<usize>
    {
        context_get_output_length(self, input_len)
    }
}

/// Implementation of Padding property
pub trait ContextWithPadding: Context {
    /// Sets the Padding property
    ///
    /// - This property can be set at the latest before the `::finalize()` call.
    fn set_property_padding(&self, padding: &Padding) -> Result<()>
    {
        let value = conv::padding_rs_to_c(padding);
        context_set_property_single(self, types::Property::Padding, value)
    }
}

/// Implementation of RC2 effective key bits property
pub trait ContextWithRc2Supported: Context {
    /// Sets the RC2 effective key bits property
    ///
    /// - Possible values are 1-1024 in steps of 1 bit.
    /// - See [`EncryptAlgorithm::UnsafeRc2`] for more information.
    ///
    /// [`EncryptAlgorithm::UnsafeRc2`]: enum.EncryptAlgorithm.html#variant.UnsafeRc2
    fn set_property_rc2_effective_key_bits(&self, rc2_eff_key_bits: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::Rc2EffectiveKeyBits, rc2_eff_key_bits)
    }
}

/// Implementation of GCM/CCM properties for `Encrypt`/`Seal`
pub trait ContextWithXcmEncryptProperties: Context {
    /// Sets the GCM tag length (in bytes)
    ///
    /// - Supported tag lengths: 4, 8, 12, 13, 14, 15, 16.
    /// - Set after [`EncryptContext::finalize()`] / [`SealContext::finalize()`] and before
    ///   [`CtxXcmEnc::get_property_gcm_tag()`].
    /// - See [`BlockCipherMode::Gcm`] for more information.
    ///
    /// [`EncryptContext::finalize()`]: struct.EncryptContext.html#method.finalize
    /// [`SealContext::finalize()`]: struct.SealContext.html#method.finalize
    /// [`CtxXcmEnc::get_property_gcm_tag()`]: trait.ContextWithXcmEncryptProperties.html#method.get_property_gcm_tag
    /// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
    fn set_property_gcm_tag_len(&self, gcm_tag_len: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::GcmTagLen, gcm_tag_len)
    }
    /// Gets the GCM tag
    ///
    /// - Get after [`EncryptContext::finalize()`] / [`SealContext::finalize()`].
    /// - See [`BlockCipherMode::Gcm`] for more information.
    ///
    /// [`EncryptContext::finalize()`]: struct.EncryptContext.html#method.finalize
    /// [`SealContext::finalize()`]: struct.SealContext.html#method.finalize
    /// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
    fn get_property_gcm_tag(&self) -> Result<Vec<u8>>
    {
        context_get_property_multiple(self, types::Property::GcmTag)
    }
    /// Sets the GCM Additional Authentication Data
    ///
    /// - AAD length can have any positive value.
    /// - Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///   [`EncryptContext::update()`] / [`SealContext::update()`] in `Encryption`/`Seal` operation.
    /// - See [`BlockCipherMode::Gcm`] for more information.
    ///
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`SealContext::update()`]: struct.SealContext.html#method.update
    /// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
    fn set_property_gcm_aad(&self, gcm_aad: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmAad, gcm_aad)
    }
    /// Sets the CCM Tag length in bytes
    ///
    /// - Supported tag lengths: 4-16 bytes in steps of 2 bytes.
    /// - Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///   [`EncryptContext::update()`] / [`SealContext::update()`].
    /// - See [`BlockCipherMode::Ccm`] for more information.
    ///
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`SealContext::update()`]: struct.SealContext.html#method.update
    /// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
    fn set_property_ccm_tag_len(&self, ccm_tag_len: usize) -> Result<()>
    {
        context_set_property_single(self, types::Property::CcmTagLen, ccm_tag_len)
    }
    /// Gets the CCM tag
    ///
    /// - Get after [`EncryptContext::finalize()`] / [`SealContext::finalize()`].
    /// - See [`BlockCipherMode::Ccm`] for more information.
    ///
    /// [`EncryptContext::finalize()`]: struct.EncryptContext.html#method.finalize
    /// [`SealContext::finalize()`]: struct.SealContext.html#method.finalize
    /// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
    fn get_property_ccm_tag(&self) -> Result<Vec<u8>>
    {
        context_get_property_multiple(self, types::Property::CcmTag)
    }
    /// Sets the CCM Additional Authentication Data
    ///
    /// - AAD length can have any positive value.
    /// - The total plaintext length must be passed.
    /// - Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///   [`EncryptContext::update()`] / [`SealContext::update()`].
    /// - See [`BlockCipherMode::Ccm`] for more information.
    ///
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`SealContext::update()`]: struct.SealContext.html#method.update
    /// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], plaintext_len: usize) -> Result<()>;
    // {
    //     OPERATION_set_input_length(self, input_len)?;
    //     crypto::context_set_property_multiple(ctx, types::Property::CcmAad, ccm_aad)
    // }
}

/// Implementation of GCM/CCM properties for `Decrypt`/`Open`
pub trait ContextWithXcmDecryptProperties: Context {
    /// Sets the GCM tag
    ///
    /// - The tag is gotten during 'Encrypt'/'Seal' operation with
    ///   [`CtxXcmEnc::get_property_gcm_tag()`].
    /// - Set after [`DecryptContext::update()`] / [`OpenContext::update()`] and before
    ///   [`DecryptContext::finalize()`] / [`OpenContext::finalize()`].
    /// - See [`BlockCipherMode::Gcm`] for more information.
    ///
    /// [`CtxXcmEnc::get_property_gcm_tag()`]: trait.ContextWithXcmEncryptProperties.html#method.get_property_gcm_tag
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`DecryptContext::finalize()`]: struct.DecryptContext.html#method.finalize
    /// [`OpenContext::finalize()`]: struct.OpenContext.html#method.finalize
    /// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
    fn set_property_gcm_tag(&self, gcm_tag: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmTag, gcm_tag)
    }
    /// Sets the GCM Additional Authentication Data
    ///
    /// - AAD is the same data that is passed during 'Encrypt'/'Seal' operation with
    ///   [`CtxXcmEnc::set_property_gcm_aad()`].
    /// - Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///   [`DecryptContext::update()`] / [`OpenContext::update()`].
    /// - See [`BlockCipherMode::Gcm`] for more information.
    ///
    /// [`CtxXcmEnc::set_property_gcm_aad()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_gcm_aad
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
    fn set_property_gcm_aad(&self, gcm_aad: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::GcmAad, gcm_aad)
    }
    /// Sets the CCM tag
    ///
    /// - The tag is gotten during 'Encrypt'/'Seal' operation with
    ///   [`CtxXcmEnc::get_property_ccm_tag()`].
    /// - Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///   [`DecryptContext::update()`] / [`OpenContext::update()`].
    /// - See [`BlockCipherMode::Ccm`] for more information.
    ///
    /// [`CtxXcmEnc::get_property_ccm_tag()`]: trait.ContextWithXcmEncryptProperties.html#method.get_property_ccm_tag
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
    fn set_property_ccm_tag(&self, ccm_tag: &[u8]) -> Result<()>
    {
        context_set_property_multiple(self, types::Property::CcmTag, ccm_tag)
    }
    /// Sets the CCM Additional Authentication Data
    ///
    /// - AAD is the same data that is passed during 'Encrypt'/'Seal' operation with
    ///   [`CtxXcmEnc::set_property_ccm_aad()`].
    /// - The total ciphertext length must be passed.
    /// - Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///   [`DecryptContext::update()`] / [`OpenContext::update()`] in `Decryption`/`Open` operation.
    /// - See [`BlockCipherMode::Ccm`] for more information.
    ///
    /// [`CtxXcmEnc::set_property_ccm_aad()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_ccm_aad
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
    fn set_property_ccm_aad(&self, ccm_aad: &[u8], ciphertext_len: usize) -> Result<()>;
    // {
    //     OPERATION_set_input_length(self, input_len)?;
    //     crypto::context_set_property_multiple(ctx, types::Property::CcmAad, ccm_aad)
    // }
}


/// Initializes the library
///
/// - Must be called before any other crypto function. Should be
///   called once in each thread that uses yaca.
/// - See [`yaca::cleanup()`].
///
/// [`yaca::cleanup()`]: fn.cleanup.html
pub fn initialize() -> Result<()>
{
    let r = unsafe {
        lib::yaca_initialize()
    };
    conv::res_c_to_rs(r)
}

/// Cleans up the library
///
/// - Must be called before exiting the thread that called [`yaca::initialize()`].
///
/// [`yaca::initialize()`]: fn.initialize.html
pub fn cleanup()
{
    unsafe {
        lib::yaca_cleanup()
    }
}

/// Safely compares requested number of bytes of two buffers
///
/// - Returns `true` if the first `length` bytes of compared buffers
///   are equal, `false` otherwise.
/// - If `length` is longer than min(first.len(), second.len()), at
///   most the common part will be checked, std::usize::MAX can safely
///   be passed here.
pub fn memcmp(first: &[u8], second: &[u8], length: usize) -> Result<bool>
{
    let min = cmp::min(first.len(), second.len());
    let length = cmp::min(length, min);
    let first = first.as_ptr() as *const c_void;
    let second = second.as_ptr() as *const c_void;
    let r = unsafe {
        lib::yaca_memcmp(first, second, length)
    };
    conv::res_c_to_rs_bool(r)
}

/// Generates random data
pub fn random_bytes(length: usize) -> Result<Vec<u8>>
{
    let mut v: Vec<u8> = Vec::with_capacity(length);
    let data = v.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        lib::yaca_randomize_bytes(data, length)
    };
    conv::res_c_to_rs(r)?;
    unsafe {
        v.set_len(length);
    };
    Ok(v)
}


fn context_set_property_single<T, U>(ctx: &T, prop: types::Property,
                                     value: U) -> Result<()>
    where T: Context + ?Sized,
          U: Integer,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let value: *const U = &value;
    let value = value as *const c_void;
    let value_len = mem::size_of::<U>();
    let r = unsafe {
        lib::yaca_context_set_property(ctx, property, value, value_len)
    };
    conv::res_c_to_rs(r)
}

// Used by set_property_ccm_aad implementators
pub(crate) fn context_set_property_multiple<T, U>(ctx: &T, prop: types::Property,
                                                  value: &[U]) -> Result<()>
    where T: Context + ?Sized,
          U: Integer,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let value_len = value.len() * mem::size_of::<U>();
    let value = value.as_ptr() as *const c_void;
    let r = unsafe {
        lib::yaca_context_set_property(ctx, property, value, value_len)
    };
    conv::res_c_to_rs(r)
}

fn context_get_property_multiple<T, U>(ctx: &T, prop: types::Property) -> Result<Vec<U>>
    where T: Context + ?Sized,
          U: Integer + Clone,
{
    let ctx = ctx.get_handle();
    let property = conv::property_rs_to_c(&prop);
    let mut value = ptr::null();
    let mut value_len = 0;
    let r = unsafe {
        lib::yaca_context_get_property(ctx, property, &mut value, &mut value_len)
    };
    conv::res_c_to_rs(r)?;
    let value_len = value_len / mem::size_of::<U>();
    Ok(common::vector_from_raw(value_len, value))
}

fn context_get_output_length<T>(ctx: &T, input_len: usize) -> Result<usize>
    where T: Context + ?Sized,
{
    let mut output_len = 0;
    let ctx = ctx.get_handle();
    let r = unsafe {
        lib::yaca_context_get_output_length(ctx, input_len, &mut output_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(output_len)
}
