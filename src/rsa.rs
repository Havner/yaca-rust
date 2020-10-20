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

use libc::c_char;
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


// TODO: try to de-duplicate this code (as well as encrypt and seal)

/// Encrypts data using a RSA public key (low-level encrypt equivalent)
///
/// - `padding` defines the padding method used in encryption.
/// - The `pub_key` has to be of a [`KeyType::RsaPublic`] type.
/// - The `plaintext` is the data to be encrypted, it can be empty.
/// - The maximum length of `plaintext` depends on the key length and
///   padding method. See [`Padding`] for details.
///
/// [`KeyType::RsaPublic`]: enum.KeyType.html#variant.RsaPublic
/// [`Padding`]: enum.Padding.html
pub fn rsa_public_encrypt(padding: &Padding, pub_key: &Key, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let pub_key = key::get_handle(&pub_key);
    let plaintext_len = plaintext.len();
    let plaintext = plaintext.as_ptr() as *const c_char;
    let mut ciphertext = ptr::null();
    let mut ciphertext_len = 0;
    let r = unsafe {
        lib::yaca_rsa_public_encrypt(padding, pub_key, plaintext, plaintext_len,
                                     &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(ciphertext_len, ciphertext))
}

/// Decrypts data using a RSA private key (low-level decrypt equivalent)
///
/// - `padding` defines the padding method that was used in encryption.
/// - The `prv_key` has to be of a [`KeyType::RsaPrivate`] type
///   and must match the public key that was used in the encryption.
/// - The `ciphertext` is the data to be decrypted.
///
/// [`KeyType::RsaPrivate`]: enum.KeyType.html#variant.RsaPrivate
pub fn rsa_private_decrypt(padding: &Padding, prv_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let prv_key = key::get_handle(&prv_key);
    let ciphertext_len = ciphertext.len();
    let ciphertext = ciphertext.as_ptr() as *const c_char;
    let mut plaintext = ptr::null();
    let mut plaintext_len = 0;
    let r = unsafe {
        lib::yaca_rsa_private_decrypt(padding, prv_key, ciphertext, ciphertext_len,
                                      &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(plaintext_len, plaintext))
}

/// Encrypts data using a RSA private key (low-level sign equivalent)
///
/// - `padding` defines the padding method used in encryption.
/// - The `prv_key` has to be of a [`KeyType::RsaPrivate`] type.
/// - The `plaintext` is the data to be enxrypted, it can be empty.
/// - The maximum length of `plaintext` depends on the key length and
///   padding method. See [`Padding`] for details.
///
/// [`KeyType::RsaPrivate`]: enum.KeyType.html#variant.RsaPrivate
/// [`Padding`]: enum.Padding.html
pub fn rsa_private_encrypt(padding: &Padding, prv_key: &Key, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let prv_key = key::get_handle(&prv_key);
    let plaintext_len = plaintext.len();
    let plaintext = plaintext.as_ptr() as *const c_char;
    let mut ciphertext = ptr::null();
    let mut ciphertext_len = 0;
    let r = unsafe {
        lib::yaca_rsa_private_encrypt(padding, prv_key, plaintext, plaintext_len,
                                      &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(ciphertext_len, ciphertext))
}

/// Decrypts data using a RSA public key (low-level verify equivalent)
///
/// - `padding` defines the padding method that was used in encryption.
/// - The `pub_key` has to be of a [`KeyType::RsaPublic`] type
///   and must match the private key that was used in the encryption.
/// - The `ciphertext` is the data to be decrypted.
///
/// [`KeyType::RsaPublic`]: enum.KeyType.html#variant.RsaPublic
pub fn rsa_public_decrypt(padding: &Padding, pub_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let pub_key = key::get_handle(&pub_key);
    let ciphertext_len = ciphertext.len();
    let ciphertext = ciphertext.as_ptr() as *const c_char;
    let mut plaintext = ptr::null();
    let mut plaintext_len = 0;
    let r = unsafe {
        lib::yaca_rsa_public_decrypt(padding, pub_key, ciphertext, ciphertext_len,
                                      &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(plaintext_len, plaintext))
}
