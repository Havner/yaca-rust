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

//! @details  This is simple API.

use libc::c_char;
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Encrypts data using a symmetric cipher
///
/// - `algo` is an encryption algorithm (select [`EncryptAlgorithm::Aes`] if unsure).
/// - `bcm` is a chaining mode (select [`BlockCipherMode::Cbc`] if unsure).
/// - `sym_key` is a symmetric encryption key (see [`Key`] for key generation functions).
/// - `iv` is an Initialization Vector (see [`EncryptContext::get_iv_length()`].
/// - `plaintext` is the data to be encrypted, can be empty.
/// - The function returns the encrypted data.
/// - It doesn't support [`BlockCipherMode::Gcm`] and [`BlockCipherMode::Ccm`].
///
/// [`EncryptAlgorithm::Aes`]: enum.EncryptAlgorithm.html#variant.Aes
/// [`BlockCipherMode::Cbc`]: enum.BlockCipherMode.html#variant.Cbc
/// [`Key`]: struct.Key.html
/// [`EncryptContext::get_iv_length()`]: struct.EncryptContext.html#method.get_iv_length
/// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
/// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
pub fn simple_encrypt(algo: &EncryptAlgorithm, bcm: &BlockCipherMode, sym_key: &Key,
                      iv: Option<&Key>, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(&sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let plaintext_len = plaintext.len();
    let plaintext = match plaintext_len {
        0 => ptr::null(),
        _ => plaintext.as_ptr() as *const c_char,
    };
    let mut ciphertext = ptr::null();
    let mut ciphertext_len = 0;
    let r = unsafe {
        lib::yaca_simple_encrypt(algo, bcm, sym_key, iv, plaintext, plaintext_len,
                                 &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    if ciphertext.is_null() {
        debug_assert!(ciphertext_len == 0);
        Ok(Vec::<u8>::new())
    } else {
        Ok(common::vector_from_raw(ciphertext_len, ciphertext))
    }
}

/// Decrypts data using a symmetric cipher
///
/// - Parameters passed must match encryption parameters used in the
///   encryption. See [`Yaca::simple_encrypt()`].
/// - `ciphertext` is the encrypted data to be decrypted.
/// - The function returns the decrypted data.
/// - It doesn't support [`BlockCipherMode::Gcm`] and [`BlockCipherMode::Ccm`].
///
/// [`Yaca::simple_encrypt()`]: fn.simple_encrypt.html
/// [`BlockCipherMode::Gcm`]: enum.BlockCipherMode.html#variant.Gcm
/// [`BlockCipherMode::Ccm`]: enum.BlockCipherMode.html#variant.Ccm
pub fn simple_decrypt(algo: &EncryptAlgorithm, bcm: &BlockCipherMode, sym_key: &Key,
                      iv: Option<&Key>, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let bcm = conv::bcm_rs_to_c(bcm);
    let sym_key = key::get_handle(&sym_key);
    let iv = match iv {
        Some(i) => key::get_handle(&i),
        None => ptr::null(),
    };
    let ciphertext_len = ciphertext.len();
    let ciphertext = match ciphertext_len {
        0 => ptr::null(),
        _ => ciphertext.as_ptr() as *const c_char,
    };
    let mut plaintext = ptr::null();
    let mut plaintext_len = 0;
    let r = unsafe {
        lib::yaca_simple_decrypt(algo, bcm, sym_key, iv, ciphertext, ciphertext_len,
                                 &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    if plaintext.is_null() {
        debug_assert!(plaintext_len == 0);
        Ok(Vec::<u8>::new())
    } else {
        Ok(common::vector_from_raw(plaintext_len, plaintext))
    }
}

/// Calculates a digest of a message
///
/// - `algo` is a digest algorithm (select [`DigestAlgorithm::Sha256`]
///   if unsure)
/// - `message` is a message from which the digest is to be
///   calculated, it can be empty.
/// - The function returns the message digest.
///
/// [`DigestAlgorithm::Sha256`]: enum.DigestAlgorithm.html#variant.Sha256
pub fn simple_calculate_digest(algo: &DigestAlgorithm, message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut digest = ptr::null();
    let mut digest_len = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_digest(algo, message, message_len,
                                          &mut digest, &mut digest_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(digest_len, digest))
}

/// Creates a signature using asymmetric private key
///
/// - `algo` is a digest algorithm that will be used.
/// - `prv_key` is a private key that will be used, algorithm is
///   deduced based on key type, supported key types:
///   * [`KeyType::RsaPrivate`],
///   * [`KeyType::DsaPrivate`],
///   * [`KeyType::EcPrivate`].
/// - `message` is message to be signed, it can be empty.
/// - The function returns a message signature.
/// - For [`DigestAlgorithm::Sha384`] and
///   [`DigestAlgorithm::Sha512`] the `RSA` key size must be bigger
///   than 512 bits.
/// - Using [`DigestAlgorithm::Md5`] algorithm for `DSA` and
///   `ECDSA` operations is prohibited.
///
/// [`KeyType::RsaPrivate`]: enum.KeyType.html#variant.RsaPrivate
/// [`KeyType::DsaPrivate`]: enum.KeyType.html#variant.DsaPrivate
/// [`KeyType::EcPrivate`]: enum.KeyType.html#variant.EcPrivate
/// [`DigestAlgorithm::Sha384`]: enum.DigestAlgorithm.html#variant.Sha384
/// [`DigestAlgorithm::Sha512`]: enum.DigestAlgorithm.html#variant.Sha512
/// [`DigestAlgorithm::Md5`]: enum.DigestAlgorithm.html#variant.Md5
pub fn simple_calculate_signature(algo: &DigestAlgorithm, prv_key: &Key,
                                  message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let prv_key = key::get_handle(&prv_key);
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut signature = ptr::null();
    let mut signature_len = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_signature(algo, prv_key, message, message_len,
                                             &mut signature, &mut signature_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(signature_len, signature))
}

/// Verifies a signature using asymmetric public key
///
/// - `algo` is a digest algorithm used to calculate the signature.
/// - `pub_key` is a matching public key to the one used to
///   calculate the signature, algorithm is deduced based on key
///   type, supported key types:
///   * [`KeyType::RsaPublic`],
///   * [`KeyType::DsaPublic`],
///   * [`KeyType::EcPublic`].
/// - `message` is the data used to calculate the signature from.
/// - `signature` is a message signature to be verified.
/// - The functions returns `true` in case of a successful verification,
///   `false` otherwise.
///
/// [`KeyType::RsaPublic`]: enum.KeyType.html#variant.RsaPublic
/// [`KeyType::DsaPublic`]: enum.KeyType.html#variant.DsaPublic
/// [`KeyType::EcPublic`]: enum.KeyType.html#variant.EcPublic
pub fn simple_verify_signature(algo: &DigestAlgorithm, pub_key: &Key,
                               message: &[u8], signature: &[u8]) -> Result<bool>
{
    let algo = conv::digest_rs_to_c(algo);
    let pub_key = key::get_handle(&pub_key);
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let signature_len = signature.len();
    let signature = signature.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_simple_verify_signature(algo, pub_key, message, message_len,
                                          signature, signature_len)
    };
    conv::res_c_to_rs_bool(r)
}

/// Calculates a HMAC of given message using symmetric key
///
/// - `algo` is a digest algorithm that will be used.
/// - `sym_key` is a key that will be used, supported key types:
///   * [`KeyType::Symmetric`],
///   * [`KeyType::Des`].
/// - `message` is a message to calculate HMAC from.
/// - The function returns message MAC.
/// - For verification, calculate message HMAC and compare with
///   received MAC using [`Yaca::memcmp()`].
///
/// [`KeyType::Symmetric`]: enum.KeyType.html#variant.Symmetric
/// [`KeyType::Des`]: enum.KeyType.html#variant.Des
/// [`Yaca::memcmp()`]: fn.memcmp.html
pub fn simple_calculate_hmac(algo: &DigestAlgorithm, sym_key: &Key,
                             message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let sym_key = key::get_handle(&sym_key);
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut mac = ptr::null();
    let mut mac_len = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_hmac(algo, sym_key, message, message_len,
                                        &mut mac, &mut mac_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(mac_len, mac))
}

/// Calculates a CMAC of given message using symmetric key
///
/// - `algo` is an encryption algorithm that will be used.
/// - `sym_key` is a key that will be used, supported key types:
///   * [`KeyType::Symmetric`],
///   * [`KeyType::Des`].
/// - `message` is a message to calculate HMAC from.
/// - The function returns message MAC.
/// - For verification, calculate message CMAC and compare with
///   received MAC using [`Yaca::memcmp()`].
///
/// [`KeyType::Symmetric`]: enum.KeyType.html#variant.Symmetric
/// [`KeyType::Des`]: enum.KeyType.html#variant.Des
/// [`Yaca::memcmp()`]: fn.memcmp.html
pub fn simple_calculate_cmac(algo: &EncryptAlgorithm, sym_key: &Key,
                             message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let sym_key = key::get_handle(&sym_key);
    let message_len = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut mac = ptr::null();
    let mut mac_len = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_cmac(algo, sym_key, message, message_len,
                                        &mut mac, &mut mac_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(mac_len, mac))
}
