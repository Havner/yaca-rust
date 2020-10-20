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
use std::ffi::CStr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Type representing a cryptography key, an Initialization Vector or
/// key generation parameters
pub struct Key {
    handle: *const c_void,
}

impl Drop for Key {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_key_destroy(self.handle as *mut c_void)
        }
    }
}

impl Key {
    /// Generates a secure key, an Initialization Vector or key
    /// generation parameters
    ///
    /// - This function is used to generate:
    ///   * symmetric keys,
    ///   * private asymmetric keys,
    ///   * key generation parameters for key types that support
    ///     them ([`DsaParams`], [`DhParams`] and [`EcParams`]).
    /// - Supported `key_length` for a specific `key_type`:
    ///   * [`Symmetric`]/[`IV`]: use [`KeyLength::Bits`], `bits` >= 8,
    ///   * [`DES`]: use [`KeyLength::Bits`], `bits` == 64, 128 or 192,
    ///   * [`RSA`]: use [`KeyLength::Bits`], `bits` >= 512,
    ///   * [`DSA`]: use [`KeyLength::Bits`], `bits` >= 512, divisble by 64,
    ///   * [`DH`]: use [`KeyLength::Dh`], see [`KeyLengthDh`] for more information,
    ///   * [`EC`]: use [`KeyLength::Ec`], see [`KeyLengthEc`] for more information.
    ///
    /// [`DsaParams`]: enum.KeyType.html#variant.DsaParams
    /// [`DhParams`]: enum.KeyType.html#variant.DhParams
    /// [`EcParams`]: enum.KeyType.html#variant.EcParams
    /// [`Symmetric`]: enum.KeyType.html#variant.Symmetric
    /// [`IV`]: enum.KeyType.html#variant.Iv
    /// [`DES`]: enum.KeyType.html#variant.Des
    /// [`RSA`]: enum.KeyType.html#variant.RsaPrivate
    /// [`DSA`]: enum.KeyType.html#variant.DsaPrivate
    /// [`DH`]: enum.KeyType.html#variant.DhPrivate
    /// [`EC`]: enum.KeyType.html#variant.EcPrivate
    /// [`KeyLength::Bits`]: enum.KeyLength.html#variant.Bits
    /// [`KeyLength::Dh`]: enum.KeyLength.html#variant.Dh
    /// [`KeyLengthDh`]: enum.KeyLengthDh.html
    /// [`KeyLength::Ec`]: enum.KeyLength.html#variant.Ec
    /// [`KeyLengthEc`]: enum.KeyLengthEc.html
    pub fn generate(key_type: &KeyType, key_length: &KeyLength) -> Result<Key>
    {
        key_generate(key_type, key_length)
    }
    /// Generates a secure private asymmetric key from parameters
    ///
    /// - This function is used to generate private asymmetric keys
    ///   based on pre-generated parameters in `params`.
    /// - This function does not support RSA keys, as it's not
    ///   possible to extract parameters from them.
    pub fn generate_from_parameters(params: &Key) -> Result<Key>
    {
        key_generate_from_parameters(params)
    }
    /// Imports a key or key generation parameters
    ///
    /// - Everywhere where either a key (of any type) or an asymmetric
    ///   key is referred in the documentation of this function key
    ///   generator parameters are also included.
    /// - This function imports a key from `data` trying to match it
    ///   to the `key_type` specified. It should autodetect both the
    ///   key format and the file format.
    /// - For [`Symmetric`], [`Initialization Vector`] and [`DES`]
    ///   keys RAW binary format and BASE64 encoded binary format are
    ///   supported.
    /// - For asymmetric keys PEM and DER file formats are supported.
    /// - Asymmetric keys can be in their default ASN1 structure
    ///   formats (like PKCS#1, SSleay or PKCS#3). Private asymmetric
    ///   keys can also be in PKCS#8 format. Additionally it is
    ///   possible to import public [`RSA`]/[`DSA`]/[`EC`] keys from
    ///   X509 certificate.
    /// - If the key is encrypted the algorithm will be autodetected
    ///   and `password` used. If it's not known if the key is encrypted
    ///   one should pass `None` as `password` and check for the
    ///   [`Error::InvalidPassword`] error code.
    /// - If the imported key will be detected as a format that does
    ///   not support encryption and `password` was passed
    ///   [`Error::InvalidParameter`] will be returned. For a list
    ///   of keys and formats that do support encryption see
    ///   [`Key::export()`] documentation.
    ///
    /// [`Symmetric`]: enum.KeyType.html#variant.Symmetric
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`DES`]: enum.KeyType.html#variant.Des
    /// [`RSA`]: enum.KeyType.html#variant.RsaPublic
    /// [`DSA`]: enum.KeyType.html#variant.DsaPublic
    /// [`EC`]: enum.KeyType.html#variant.EcPublic
    /// [`Error::InvalidPassword`]: enum.Error.html#variant.InvalidPassword
    /// [`Error::InvalidParameter`]: enum.Error.html#variant.InvalidParameter
    /// [`Key::export()`]: struct.Key.html#method.export
    pub fn import(data: &[u8], key_type: &KeyType, password: Option<&CStr>) -> Result<Key>
    {
        key_import(data, key_type, password)
    }
    /// Exports a key or key generation parameters to arbitrary format
    ///
    /// - Everywhere where either a key (of any type) or an asymmetric
    ///   key is referred in the documentation of this function key
    ///   generator parameters are also included.
    /// - This function exports the key to an arbitrary `key_format` and
    ///   `key_file_fmt`.
    /// - For key formats two values are allowed:
    ///   * [`KeyFormat::Default`]: this is the only option possible in case of symmetric keys
    ///                             (or Initialization Vector), for asymmetric keys it will
    ///                             export to their default ASN1 structure format
    ///                             (e.g. PKCS#1, SSLeay, PKCS#3).
    ///   * [`KeyFormat::Pkcs8`]: this will only work for private asymmetric keys.
    /// - The following file formats are supported:
    ///   * [`KeyFileFormat::Raw`]: used only for symmetric, raw binary format,
    ///   * [`KeyFileFormat::Base64`]: used only for symmetric, BASE64 encoded binary form,
    ///   * [`KeyFileFormat::Pem`]: used only for asymmetric, PEM file format,
    ///   * [`KeyFileFormat::Der`]: used only for asymmetric, DER file format.
    /// - Encryption is supported and optional for RSA/DSA private keys in the
    ///   [`KeyFormat::Default`] with [`KeyFileFormat::Pem`] format. If no `password` is
    ///   provided the exported key will be unencrypted. The encryption algorithm used
    ///   in this case is AES-256-CBC.
    /// - Encryption is obligatory for [`KeyFormat::Pkcs8`] format (for both,
    ///   [`KeyFileFormat::Pem`] and [`KeyFileFormat::Der`] file formats). If no
    ///   `password` is provided the [`Error::InvalidParameter`] will be returned. The
    ///   encryption algorithm used in this case is AES-256-CBC. The key is generated from
    ///   `password` using PBKDF2 with HMAC-SHA1 function and 2048 iterations.
    /// - Encryption is not supported for the symmetric, public keys and key generation
    ///   parameters in all their supported formats. If a `password` is provided in such
    ///   case the [`Error::InvalidParameter`] will be returned.
    ///
    /// [`KeyFormat::Default`]: enum.KeyFormat.html#variant.Default
    /// [`KeyFormat::Pkcs8`]: enum.KeyFormat.html#variant.Pkcs8
    /// [`KeyFileFormat::Raw`]: enum.KeyFileFormat.html#variant.Raw
    /// [`KeyFileFormat::Base64`]: enum.KeyFileFormat.html#variant.Base64
    /// [`KeyFileFormat::Pem`]: enum.KeyFileFormat.html#variant.Pem
    /// [`KeyFileFormat::Der`]: enum.KeyFileFormat.html#variant.Der
    /// [`Error::InvalidParameter`]: enum.Error.html#variant.InvalidParameter
    pub fn export(&self, key_fmt: &KeyFormat, key_file_fmt: &KeyFileFormat,
                  password: Option<&CStr>) -> Result<Vec<u8>>
    {
        key_export(self, key_fmt, key_file_fmt, password)
    }
    /// Extracts public key from a private one
    pub fn extract_public(&self) -> Result<Key>
    {
        key_extract_public(self)
    }
    /// Extracts parameters from a private or a public key
    ///
    ///  - This function does not support `RSA` keys.
    pub fn extract_parameters(&self) -> Result<Key>
    {
        key_extract_parameters(self)
    }
    /// Derives a shared secret using Diffie-Helmann or EC
    /// Diffie-Helmann key exchange protocol
    ///
    /// - `prv_key` is our private key.
    /// - `pub_key` is a peer public key.
    /// - The returned secret should not be used as a symmetric key.
    ///   To produce a symmetric key pass the secret to a key
    ///   derivation function (KDF) or a message digest function.
    /// - Both the keys passed should be of [`DH`] or [`EC`] type.
    ///
    /// [`DH`]: enum.KeyType.html#variant.DhPrivate
    /// [`EC`]: enum.KeyType.html#variant.EcPrivate
    pub fn derive_dh(prv_key: &Key, pub_key: &Key) -> Result<Vec<u8>>
    {
        key_derive_dh(prv_key, pub_key)
    }
    /// Derives a key material from shared secret
    ///
    /// - `kdf` is a key derivation function
    /// - `digest` is a digest algorithm used in key derivation
    /// - `secret` is a shared secret that can be derived for instance
    ///   from [`Key::derive_dh()`].
    /// - The optional `info` parameter is ANSI X9.42 OtherInfo or
    ///   ANSI X9.62 SharedInfo structure, more information can be
    ///   found in ANSI X9.42/62 standard specification.
    /// - The returned key material (of `key_material_len` length) or
    ///   separate parts of it can be used to import a symmetric key
    ///   with [`Key::import()`].
    ///
    /// [`Key::derive_dh()`]: struct.Key.html#method.derive_dh
    /// [`Key::import()`]: struct.Key.html#method.import
    pub fn derive_kdf(kdf: &Kdf, algo: &DigestAlgorithm,
                      secret: &[u8], info: Option<&[u8]>,
                      key_material_len: usize) -> Result<Vec<u8>>
    {
        key_derive_kdf(kdf, algo, secret, info, key_material_len)
    }
    /// Derives a key from user password (PKCS #5 a.k.a. pbkdf2 algorithm)
    ///
    /// - `password` is a user password.
    /// - optional `salt` can be passed.
    /// - `iterations` defines number of iterations during the generation.
    /// - `algo` is a digest algorithm used in key generation.
    /// - the returned key will be of `key_bit_len` length.
    pub fn derive_pbkdf2(password: &CStr, salt: Option<&[u8]>, iterations: usize,
                         algo: &DigestAlgorithm, key_bit_len: usize) -> Result<Key>
    {
        key_derive_pbkdf2(password, salt, iterations, algo, key_bit_len)
    }
    /// Gets key's type
    pub fn get_type(&self) -> Result<KeyType>
    {
        key_get_type(&self)
    }
    /// Gets key's length
    ///
    /// - Can be used on any symmetric (including an Initialization
    ///   Vector) or asymmetric key (including key generation
    ///   parameters).
    /// - For Diffie-Helmann returns prime length in
    ///   [`KeyLength::Bits`]. Values of [`KeyLengthDh`] used to
    ///   generate the key/parameters in [`Key::generate()`] are not
    ///   restored.
    /// - For Elliptic Curves returns values from [`KeyLengthEc`].
    ///
    /// [`KeyLength::Bits`]: enum.KeyLength.html#variant.Bits
    /// [`KeyLengthDh`]: enum.KeyLengthDh.html
    /// [`KeyLengthEc`]: enum.KeyLengthEc.html
    /// [`Key::generate()`]: struct.Key.html#method.generate
    pub fn get_length(&self) -> Result<KeyLength>
    {
        key_get_length(&self)
    }
}

// Used by the C wrappers
#[inline]
pub(crate) fn get_handle(key: &Key) -> *const c_void
{
    key.handle
}

// Used to compose Keys in Seal
#[inline]
pub(crate) fn new_key(handle: *const c_void) -> Key
{
    Key{handle}
}


#[inline]
fn key_get_type(key: &Key) -> Result<KeyType>
{
    let mut kt = 0;
    let r = unsafe {
        lib::yaca_key_get_type(key.handle, &mut kt)
    };
    conv::res_c_to_rs(r)?;
    Ok(conv::key_type_c_to_rs(kt))
}

#[inline]
fn key_get_length(key: &Key) -> Result<KeyLength>
{
    let mut kl = 0;
    let r = unsafe {
        lib::yaca_key_get_bit_length(key.handle, &mut kl)
    };
    conv::res_c_to_rs(r)?;
    Ok(conv::key_length_c_to_rs(kl))
}

#[inline]
fn key_import(data: &[u8], key_type: &KeyType, password: Option<&CStr>) -> Result<Key>
{
    let key_type = conv::key_type_rs_to_c(key_type);
    let password = match password {
        Some(p) => p.as_ptr(),
        None => ptr::null(),
    };
    let data_len = data.len();
    let data = data.as_ptr() as *const c_char; // u8 vs i8
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_import(key_type, password, data,
                             data_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}

#[inline]
fn key_export(key: &Key, key_fmt: &KeyFormat, key_file_fmt: &KeyFileFormat,
              password: Option<&CStr>) -> Result<Vec<u8>>
{
    let key_fmt = conv::key_format_rs_to_c(key_fmt);
    let key_file_fmt = conv::key_file_format_rs_to_c(key_file_fmt);
    let password = match password {
        Some(p) => p.as_ptr(),
        None => ptr::null(),
    };
    let mut data = ptr::null();
    let mut data_len = 0;
    let r = unsafe {
        lib::yaca_key_export(key.handle, key_fmt, key_file_fmt,
                             password, &mut data, &mut data_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(yaca_common::vector_from_raw(data_len, data))
}

#[inline]
fn key_generate(key_type: &KeyType, key_length: &KeyLength) -> Result<Key>
{
    let key_type = conv::key_type_rs_to_c(key_type);
    let key_bit_len = conv::key_length_rs_to_c(key_length);
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_generate(key_type, key_bit_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}

#[inline]
fn key_generate_from_parameters(params: &Key) -> Result<Key>
{
    let params = params.handle;
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_generate_from_parameters(params, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}

#[inline]
fn key_extract_public(prv_key: &Key) -> Result<Key>
{
    let prv_key = prv_key.handle;
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_extract_public(prv_key, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}

#[inline]
fn key_extract_parameters(key: &Key) -> Result<Key>
{
    let key = key.handle;
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_extract_parameters(key, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}

#[inline]
fn key_derive_dh(prv_key: &Key, pub_key: &Key) -> Result<Vec<u8>>
{
    let prv_key = prv_key.handle;
    let pub_key = pub_key.handle;
    let mut secret = ptr::null();
    let mut secret_len = 0;
    let r = unsafe {
        lib::yaca_key_derive_dh(prv_key, pub_key, &mut secret, &mut secret_len)
    };
    conv::res_c_to_rs(r)?;
    Ok(common::vector_from_raw(secret_len, secret))
}

#[inline]
fn key_derive_kdf(kdf: &Kdf, algo: &DigestAlgorithm,
                  secret: &[u8], info: Option<&[u8]>,
                  key_material_len: usize) -> Result<Vec<u8>>
{
    let kdf = conv::kdf_rs_to_c(kdf);
    let algo = conv::digest_rs_to_c(algo);
    let secret_len = secret.len();
    let secret = secret.as_ptr() as *const c_char;
    let info_len;
    let info = match info {
        Some(i) => {
            info_len = i.len();
            i.as_ptr() as *const c_char
        },
        None => {
            info_len = 0;
            ptr::null()
        }
    };
    let mut key_material = ptr::null();
    let r = unsafe {
        lib::yaca_key_derive_kdf(kdf, algo, secret, secret_len,
                                 info, info_len,
                                 key_material_len, &mut key_material)
    };
    conv::res_c_to_rs(r)?;
    Ok(yaca_common::vector_from_raw(key_material_len, key_material))
}

#[inline]
fn key_derive_pbkdf2(password: &CStr, salt: Option<&[u8]>, iterations: usize,
                     algo: &DigestAlgorithm, key_bit_len: usize) -> Result<Key>
{
    let password = password.as_ptr();
    let salt_len;
    let salt = match salt {
        Some(s) => {
            salt_len = s.len();
            s.as_ptr() as *const c_char
        },
        None => {
            salt_len = 0;
            ptr::null()
        },
    };
    let algo = conv::digest_rs_to_c(algo);
    let mut handle = ptr::null();
    let r = unsafe {
        lib::yaca_key_derive_pbkdf2(password, salt, salt_len, iterations,
                                    algo, key_bit_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    debug_assert!(!handle.is_null());
    Ok(Key{handle})
}
