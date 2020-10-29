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

use libc::{c_char, c_int, c_void, size_t};
use std::slice;
use std::ptr;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::crypto::Context;
use crate::*;


pub(crate) fn vector_from_raw<U, T>(length: usize, data: *const U) -> Vec<T>
    where T: Clone,
{
    debug_assert!(!data.is_null());
    debug_assert!(length > 0);
    unsafe {
        let v = slice::from_raw_parts(data as *const T, length).to_vec();
        lib::yaca_free(data as *mut c_void);
        v
    }
}


type FfiRsaFunc = unsafe extern "C" fn(c_int, *const c_void, *const c_char, size_t,
                                       *mut *const c_char, *mut size_t) -> c_int;

pub(crate) fn rsa(padding: &Padding, key: &Key, text: &[u8],
                  rsa: FfiRsaFunc) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let key = key::get_handle(&key);
    let text_len = text.len();
    let text = text.as_ptr() as *const c_char;
    let mut resulttext = ptr::null();
    let mut resulttext_len = 0;
    let r = unsafe {
        rsa(padding, key, text, text_len,
             &mut resulttext, &mut resulttext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(vector_from_raw(resulttext_len, resulttext))
}


type FfiHashUpdFunc = unsafe extern "C" fn(*mut c_void, *const c_char, size_t) -> c_int;
type FfiHashFinFunc = unsafe extern "C" fn(*mut c_void, *mut c_char, *mut size_t) -> c_int;

pub(crate) fn hash_upd<C>(ctx: &C, message: &[u8], update: FfiHashUpdFunc) -> Result<()>
    where C: Context
{
    let ctx = ctx.get_handle();
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let r = unsafe {
        update(ctx, message, message_len)
    };
    conv::res_c_to_rs(r)
}

pub(crate) fn hash_fin<C>(ctx: &C, finalize: FfiHashFinFunc) -> Result<Vec<u8>>
    where C: Context
{
    let output_len = ctx.get_output_length(0)?;
    debug_assert!(output_len > 0);
    let ctx = ctx.get_handle();
    let mut digest_vec: Vec<u8> = Vec::with_capacity(output_len);
    let digest = digest_vec.as_mut_ptr() as *mut c_char;
    let mut digest_len = output_len;
    let r = unsafe {
        finalize(ctx, digest, &mut digest_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(digest_len <= output_len);
    unsafe {
        digest_vec.set_len(digest_len);
    };
    Ok(digest_vec)
}

type FfiSignInitFunc = unsafe extern "C" fn(*mut *mut c_void, c_int, *const c_void) -> c_int;

pub(crate) fn sign_init(algo: &DigestAlgorithm, key: &Key, initialize: FfiSignInitFunc) -> Result<*mut c_void>
{
    let algo = conv::digest_rs_to_c(algo);
    let key = key::get_handle(key);
    let mut handle = ptr::null_mut();
    let r = unsafe {
        initialize(&mut handle, algo, key)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(handle)
}

type FfiEncInitFunc = unsafe extern "C" fn(*mut *mut c_void, c_int, c_int,
                                           *const c_void, *const c_void) -> c_int;
type FfiEncUpdFunc = unsafe extern "C" fn(*mut c_void, *const c_char, size_t,
                                          *mut c_char, *mut size_t) -> c_int;
type FfiEncFinFunc = unsafe extern "C" fn(*mut c_void, *mut c_char,
                                          *mut size_t) -> c_int;

pub(crate) fn enc_init(algo: &EncryptAlgorithm, bcm: &BlockCipherMode,
                       sym_key: &Key, iv: Option<&Key>, init: FfiEncInitFunc) -> Result<*mut c_void>
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
        init(&mut handle, algo, bcm, sym_key, iv)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(handle)
}

pub(crate) fn enc_set_input_length<C>(ctx: &C, input_len: usize, update: FfiEncUpdFunc) -> Result<()>
    where C: Context,
{
    let ctx = ctx.get_handle();
    let text = ptr::null();
    let text_len = input_len;
    let resulttext = ptr::null_mut();
    let mut resulttext_len = 0;
    let r = unsafe {
        update(ctx, text, text_len, resulttext, &mut resulttext_len)
    };
    conv::res_c_to_rs(r)
}

pub(crate) fn enc_upd<C>(ctx: &C, text: &[u8], update: FfiEncUpdFunc) -> Result<Vec<u8>>
    where C: Context,
{
    let text_len = text.len();
    let output_len = ctx.get_output_length(text_len)?;
    let ctx = ctx.get_handle();
    let text = match text_len {
        0 => ptr::null(),
        _ => text.as_ptr() as *const c_char,
    };
    let mut resulttext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut resulttext_len = 0;
    let resulttext = resulttext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        update(ctx, text, text_len, resulttext, &mut resulttext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(resulttext_len <= output_len);
    unsafe {
        resulttext_vec.set_len(resulttext_len);
    };
    Ok(resulttext_vec)
}

pub(crate) fn enc_fin<C>(ctx: &C, finalize: FfiEncFinFunc) -> Result<Vec<u8>>
    where C: Context,
{
    let output_len = ctx.get_output_length(0)?;
    let ctx = ctx.get_handle();
    let mut resulttext_vec: Vec<u8> = Vec::with_capacity(output_len);
    let mut resulttext_len = 0;
    let resulttext = resulttext_vec.as_mut_ptr() as *mut c_char;
    let r = unsafe {
        finalize(ctx, resulttext, &mut resulttext_len)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(resulttext_len <= output_len);
    unsafe {
        resulttext_vec.set_len(resulttext_len);
    };
    Ok(resulttext_vec)
}
