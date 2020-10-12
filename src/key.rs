use libc::{c_int, size_t, c_void, c_char};
use std::ptr;
use std::slice;
use std::ffi::{CStr, CString};

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Type representing a cryptography key or key generation parameters.
pub struct Key {
    handle: *const c_void,
}

// TEMPORARY implementation
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let kff = match self.get_type().unwrap() {
            KeyType::Symmetric | KeyType::Des | KeyType::Iv => KeyFileFormat::Base64,
            _ => KeyFileFormat::Pem,
        };
        let v = crate::key::key_export(self, &KeyFormat::Default,
                                       &kff, None).unwrap();
        let s = CString::new(v).unwrap().into_string().unwrap();
        writeln!(f, "{:?} {:?}:", self.get_type().unwrap(), self.get_length().unwrap())?;
        write!(f, "{}", s)
    }
}

impl Drop for Key {
    fn drop(&mut self)
    {
        unsafe {
            lib::yaca_key_destroy(self.handle as *mut c_void);
        };
    }
}

impl Key {
    /// Generates a secure key or key generation parameters
    /// (or an Initialization Vector).
    pub fn generate(key_type: &KeyType, key_length: &KeyLength) -> Result<Key>
    {
        key_generate(key_type, key_length)
    }

    /// Generates a secure private asymmetric key from parameters.
    pub fn generate_from_parameters(params: &Key) -> Result<Key>
    {
        key_generate_from_parameters(params)
    }

    /// Imports a key or key generation parameters.
    pub fn import(data: &[u8], key_type: &KeyType, password: Option<&CStr>) -> Result<Key>
    {
        key_import(data, key_type, password)
    }

    /// Exports a key or key generation parameters to arbitrary format.
    pub fn export(&self, key_fmt: &KeyFormat, key_file_fmt: &KeyFileFormat,
                  password: Option<&CStr>) -> Result<Vec<u8>>
    {
        key_export(self, key_fmt, key_file_fmt, password)
    }

    /// Extracts public key from a private one.
    pub fn extract_public(&self) -> Result<Key>
    {
        key_extract_public(self)
    }

    /// Extracts parameters from a private or a public key.
    pub fn extract_parameters(&self) -> Result<Key>
    {
        key_extract_parameters(self)
    }

    /// Derives a shared secret using Diffie-Helmann or EC Diffie-Helmann
    /// key exchange protocol.
    pub fn derive_dh(prv_key: &Key, pub_key: &Key) -> Result<Vec<u8>>
    {
        key_derive_dh(prv_key, pub_key)
    }

    /// Derives a key material from shared secret.
    pub fn derive_kdf(kdf: &Kdf, algo: &DigestAlgorithm,
                      secret: &[u8], info: Option<&[u8]>,
                      key_material_len: usize) -> Result<Vec<u8>>
    {
        key_derive_kdf(kdf, algo, secret, info, key_material_len)
    }

    /// Derives a key from user password (PKCS #5 a.k.a. pbkdf2 algorithm).
    pub fn derive_pbkdf2(password: &CStr, salt: Option<&[u8]>, iterations: usize,
                         algo: &DigestAlgorithm, key_bit_len: usize) -> Result<Key>
    {
        key_derive_pbkdf2(password, salt, iterations, algo, key_bit_len)
    }
    /// Gets key's type.
    pub fn get_type(&self) -> Result<KeyType>
    {
        key_get_type(&self)
    }
    /// Gets key's length.
    pub fn get_length(&self) -> Result<KeyLength>
    {
        key_get_length(&self)
    }
}

// Library private
pub fn get_handle(key: &Key) -> *const c_void
{
    key.handle
}

// Library private
pub fn new_key(handle: *const c_void) -> Key
{
    Key{handle}
}


/// Gets key's type.
pub fn key_get_type(key: &Key) -> Result<KeyType>
{
    let mut kt: c_int = -1;
    let r = unsafe {
        lib::yaca_key_get_type(key.handle, &mut kt)
    };
    conv::res_c_to_rs(r)?;
    Ok(conv::key_type_c_to_rs(kt))
}

/// Gets key's length.
pub fn key_get_length(key: &Key) -> Result<KeyLength>
{
    let mut kl: size_t = 0;
    let r = unsafe {
        lib::yaca_key_get_bit_length(key.handle, &mut kl)
    };
    conv::res_c_to_rs(r)?;
    Ok(conv::key_length_c_to_rs(kl))
}

/// Imports a key or key generation parameters.
pub fn key_import(data: &[u8], key_type: &KeyType, password: Option<&CStr>) -> Result<Key>
{
    let key_type = conv::key_type_rs_to_c(key_type);
    let password = match password {
        Some(p) => p.as_ptr(),
        None => ptr::null(),
    };
    let data_len: size_t = data.len();
    let data = data.as_ptr() as *const c_char; // u8 vs i8
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_import(key_type, password, data,
                             data_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}

/// Exports a key or key generation parameters to arbitrary format.
pub fn key_export(key: &Key, key_fmt: &KeyFormat, key_file_fmt: &KeyFileFormat,
                  password: Option<&CStr>) -> Result<Vec<u8>>
{
    let key_fmt = conv::key_format_rs_to_c(key_fmt);
    let key_file_fmt = conv::key_file_format_rs_to_c(key_file_fmt);
    let password = match password {
        Some(p) => p.as_ptr(),
        None => ptr::null(),
    };
    let mut data: *const c_void = ptr::null();
    let mut data_len: size_t = 0;
    let r = unsafe {
        lib::yaca_key_export(key.handle, key_fmt, key_file_fmt,
                             password, &mut data, &mut data_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!data.is_null());
    assert!(data_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(data as *const u8,
                                  data_len as usize).to_vec();
        lib::yaca_free(data as *mut c_void);
    };
    Ok(v)
}

/// Generates a secure key or key generation parameters
/// (or an Initialization Vector).
pub fn key_generate(key_type: &KeyType, key_length: &KeyLength) -> Result<Key>
{
    let key_type = conv::key_type_rs_to_c(key_type);
    let key_bit_len = conv::key_length_rs_to_c(key_length);
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_generate(key_type, key_bit_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}

/// Generates a secure private asymmetric key from parameters.
pub fn key_generate_from_parameters(params: &Key) -> Result<Key>
{
    let params = params.handle;
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_generate_from_parameters(params, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}

/// Extracts public key from a private one.
pub fn key_extract_public(prv_key: &Key) -> Result<Key>
{
    let prv_key = prv_key.handle;
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_extract_public(prv_key, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}

/// Extracts parameters from a private or a public key.
pub fn key_extract_parameters(key: &Key) -> Result<Key>
{
    let key = key.handle;
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_extract_parameters(key, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}

/// Derives a shared secret using Diffie-Helmann or EC Diffie-Helmann
/// key exchange protocol.
pub fn key_derive_dh(prv_key: &Key, pub_key: &Key) -> Result<Vec<u8>>
{
    let prv_key = prv_key.handle;
    let pub_key = pub_key.handle;
    let mut secret: *const c_char = ptr::null();
    let mut secret_len: size_t = 0;
    let r = unsafe {
        lib::yaca_key_derive_dh(prv_key, pub_key, &mut secret, &mut secret_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!secret.is_null());
    assert!(secret_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(secret as *const u8,
                                  secret_len as usize).to_vec();
        lib::yaca_free(secret as *mut c_void);
    };
    Ok(v)
}

/// Derives a key material from shared secret.
pub fn key_derive_kdf(kdf: &Kdf, algo: &DigestAlgorithm,
                      secret: &[u8], info: Option<&[u8]>,
                      key_material_len: usize) -> Result<Vec<u8>>
{
    let kdf = conv::kdf_rs_to_c(kdf);
    let algo = conv::digest_rs_to_c(algo);
    let secret_len: size_t = secret.len();
    let secret = secret.as_ptr() as *const c_char;
    let info_len: size_t;
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
    let key_material_len: size_t = key_material_len;
    let mut key_material: *const c_char = ptr::null();
    let r = unsafe {
        lib::yaca_key_derive_kdf(kdf, algo, secret, secret_len,
                                 info, info_len,
                                 key_material_len, &mut key_material)
    };
    conv::res_c_to_rs(r)?;
    assert!(!key_material.is_null());
    assert!(key_material_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(key_material as *const u8,
                                  key_material_len as usize).to_vec();
        lib::yaca_free(key_material as *mut c_void);
    };
    Ok(v)
}

/// Derives a key from user password (PKCS #5 a.k.a. pbkdf2 algorithm).
pub fn key_derive_pbkdf2(password: &CStr, salt: Option<&[u8]>, iterations: usize,
                         algo: &DigestAlgorithm, key_bit_len: usize) -> Result<Key>
{
    let password = password.as_ptr();
    let salt_len: size_t;
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
    let iterations: size_t = iterations;
    let algo = conv::digest_rs_to_c(algo);
    let key_bit_len: size_t = key_bit_len;
    let mut handle: *const c_void = ptr::null();
    let r = unsafe {
        lib::yaca_key_derive_pbkdf2(password, salt, salt_len, iterations,
                                    algo, key_bit_len, &mut handle)
    };
    conv::res_c_to_rs(r)?;
    assert!(!handle.is_null());
    Ok(Key{handle})
}
