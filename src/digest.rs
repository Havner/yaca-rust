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
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::Context;
use crate::*;


/// Context for `Digest` operations
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
    /// Initializes a digest context
    ///
    /// - `algo` is a digest algorithm that will be used to calculate
    ///   message digest.
    pub fn initialize(algo: &DigestAlgorithm) -> Result<DigestContext>
    {
        digest_initialize(algo)
    }
    /// Feeds the message into the message digest algorithm
    ///
    /// - `message` is a chunk of data to calculate digest from.
    pub fn update(&self, message: &[u8]) -> Result<()>
    {
        digest_update(self, message)
    }
    /// Calculates the final digest
    ///
    /// - Returns the calculated digest.
    /// - Skipping [`DigestContext::update()`] and calling only
    ///   `DigestContext::finalize()` will produce a digest of an empty message.
    ///
    /// [`DigestContext::update()`]: struct.DigestContext.html#method.update
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
    debug_assert!(!handle.is_null());
    Ok(DigestContext{handle})
}

#[inline]
fn digest_update(ctx: &DigestContext, message: &[u8]) -> Result<()>
{
    common::hash_upd(ctx, message, lib::yaca_digest_update)
}

#[inline]
fn digest_finalize(ctx: &DigestContext) -> Result<Vec<u8>>
{
    common::hash_fin(ctx, lib::yaca_digest_finalize)
}
