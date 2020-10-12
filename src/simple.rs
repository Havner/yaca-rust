use libc::{size_t, c_void, c_char};
use std::ptr;
use std::slice;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Encrypts data using a symmetric cipher.
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
    let plaintext_len: size_t = plaintext.len();
    let plaintext = match plaintext_len {
        0 => ptr::null(),
        _ => plaintext.as_ptr() as *const c_char,
    };
    let mut ciphertext: *const c_char = ptr::null();
    let mut ciphertext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_encrypt(algo, bcm, sym_key, iv, plaintext, plaintext_len,
                                 &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    match ciphertext.is_null() {
        true => {
            assert!(ciphertext_len == 0);
            Ok(Vec::<u8>::new())
        },
        false => {
            assert!(ciphertext_len > 0);
            let v;
            unsafe {
                v = slice::from_raw_parts(ciphertext as *const u8,
                                          ciphertext_len as usize).to_vec();
                lib::yaca_free(ciphertext as *mut c_void);
            };
            Ok(v)
        },
    }
}

/// Decrypts data using a symmetric cipher.
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
    let ciphertext_len: size_t = ciphertext.len();
    let ciphertext = match ciphertext_len {
        0 => ptr::null(),
        _ => ciphertext.as_ptr() as *const c_char,
    };
    let mut plaintext: *const c_char = ptr::null();
    let mut plaintext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_decrypt(algo, bcm, sym_key, iv, ciphertext, ciphertext_len,
                                 &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    match plaintext.is_null() {
        true => {
            assert!(plaintext_len == 0);
            Ok(Vec::<u8>::new())
        },
        false => {
            assert!(plaintext_len > 0);
            let v;
            unsafe {
                v = slice::from_raw_parts(plaintext as *const u8,
                                          plaintext_len as usize).to_vec();
                lib::yaca_free(plaintext as *mut c_void);
            };
            Ok(v)
        },
    }
}

/// Calculates a digest of a message.
pub fn simple_calculate_digest(algo: &DigestAlgorithm, message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut digest: *const c_char = ptr::null();
    let mut digest_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_digest(algo, message, message_len,
                                          &mut digest, &mut digest_len)
    };
    conv::res_c_to_rs(r)?;
    let v;
    unsafe {
        v = slice::from_raw_parts(digest as *const u8, digest_len as usize).to_vec();
        lib::yaca_free(digest as *mut c_void);
    }
    Ok(v)
}

/// Creates a signature using asymmetric private key.
pub fn simple_calculate_signature(algo: &DigestAlgorithm, prv_key: &Key,
                                  message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let prv_key = key::get_handle(&prv_key);
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut signature: *const c_char = ptr::null();
    let mut signature_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_signature(algo, prv_key, message, message_len,
                                             &mut signature, &mut signature_len)
    };
    conv::res_c_to_rs(r)?;
    let v;
    unsafe {
        v = slice::from_raw_parts(signature as *const u8, signature_len as usize).to_vec();
        lib::yaca_free(signature as *mut c_void);
    }
    Ok(v)
}

/// Verifies a signature using asymmetric public key.
pub fn simple_verify_signature(algo: &DigestAlgorithm, pub_key: &Key,
                               message: &[u8], signature: &[u8]) -> Result<bool>
{
    let algo = conv::digest_rs_to_c(algo);
    let pub_key = key::get_handle(&pub_key);
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let signature_len: size_t = signature.len();
    let signature = signature.as_ptr() as *const c_char;
    let r = unsafe {
        lib::yaca_simple_verify_signature(algo, pub_key, message, message_len,
                                          signature, signature_len)
    };
    conv::res_c_to_rs_bool(r)
}

/// Calculates a HMAC of given message using symmetric key.
pub fn simple_calculate_hmac(algo: &DigestAlgorithm, sym_key: &Key,
                             message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::digest_rs_to_c(algo);
    let sym_key = key::get_handle(&sym_key);
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut mac: *const c_char = ptr::null();
    let mut mac_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_hmac(algo, sym_key, message, message_len,
                                        &mut mac, &mut mac_len)
    };
    conv::res_c_to_rs(r)?;
    let v;
    unsafe {
        v = slice::from_raw_parts(mac as *const u8, mac_len as usize).to_vec();
        lib::yaca_free(mac as *mut c_void);
    };
    Ok(v)
}

/// Calculates a CMAC of given message using symmetric key.
pub fn simple_calculate_cmac(algo: &EncryptAlgorithm, sym_key: &Key,
                             message: &[u8]) -> Result<Vec<u8>>
{
    let algo = conv::encrypt_rs_to_c(algo);
    let sym_key = key::get_handle(&sym_key);
    let message_len: size_t = message.len();
    let message = message.as_ptr() as *const c_char;
    let mut mac: *const c_char = ptr::null();
    let mut mac_len: size_t = 0;
    let r = unsafe {
        lib::yaca_simple_calculate_cmac(algo, sym_key, message, message_len,
                                        &mut mac, &mut mac_len)
    };
    conv::res_c_to_rs(r)?;
    let v;
    unsafe {
        v = slice::from_raw_parts(mac as *const u8, mac_len as usize).to_vec();
        lib::yaca_free(mac as *mut c_void);
    };
    Ok(v)
}
