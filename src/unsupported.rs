/*
 *  Copyright (c) 2021 Samsung Electronics Co., Ltd All Rights Reserved
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
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


pub fn key_rsa_generate(key_length: &KeyLength, key_pub_exp: u64) -> Result<Key>
{
    let key_bit_len = conv::key_length_rs_to_c(key_length);
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_rsa_generate(key_bit_len, key_pub_exp, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(key::new_key(handle))
}

pub fn key_rsa_get_public_exponent(key: &Key) -> Result<u64>
{
    let mut pe = 0;
    let r = unsafe {
        lib::yaca_key_rsa_get_public_exponent(key::get_handle(key), &mut pe)
    };
    conv::res_c_to_rs(r)?;
    Ok(pe)
}

const YACA_DIGEST_NONE: c_int = -1;

type FfiRsa2Func = unsafe extern "C" fn(c_int, c_int, *const c_void, *const c_char, size_t,
                                        *mut *const c_char, *mut size_t) -> c_int;

fn rsa2(padding: &Padding, digest: Option<&DigestAlgorithm>, key: &Key, text: &[u8],
        rsa2: FfiRsa2Func) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let digest = match digest {
        None => YACA_DIGEST_NONE,
        Some(d) => conv::digest_rs_to_c(d),
    };
    let key = key::get_handle(&key);
    let text_len = text.len();
    let text = text.as_ptr() as *const c_char;
    let mut resulttext = ptr::null();
    let mut resulttext_len = 0;
    let r = unsafe {
        rsa2(padding, digest, key, text, text_len,
             &mut resulttext, &mut resulttext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(resulttext_len, resulttext))
}

pub fn rsa_public_encrypt_2(padding: &Padding, digest: Option<&DigestAlgorithm>, pub_key: &Key, plaintext: &[u8]) -> Result<Vec<u8>>
{
    rsa2(padding, digest, pub_key, plaintext, lib::yaca_rsa_public_encrypt_2)
}

pub fn rsa_private_decrypt_2(padding: &Padding, digest: Option<&DigestAlgorithm>, prv_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    rsa2(padding, digest, prv_key, ciphertext, lib::yaca_rsa_private_decrypt_2)
}
