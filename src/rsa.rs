use libc::{size_t, c_void, c_char};
use std::ptr;
use std::slice;

use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Encrypts data using a RSA public key (low-level encrypt equivalent).
pub fn rsa_public_encrypt(padding: &Padding, pub_key: &Key, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let pub_key = key::get_handle(&pub_key);
    let plaintext_len: size_t = plaintext.len();
    let plaintext = plaintext.as_ptr() as *const c_char;
    let mut ciphertext = ptr::null() as *const c_char;
    let mut ciphertext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_rsa_public_encrypt(padding, pub_key, plaintext, plaintext_len,
                                     &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!ciphertext.is_null());
    assert!(ciphertext_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(ciphertext as *const u8, ciphertext_len).to_vec();
        lib::yaca_free(ciphertext as *mut c_void);
    };
    Ok(v)
}

/// Decrypts data using a RSA private key (low-level decrypt equivalent).
pub fn rsa_private_decrypt(padding: &Padding, prv_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let prv_key = key::get_handle(&prv_key);
    let ciphertext_len: size_t = ciphertext.len();
    let ciphertext = ciphertext.as_ptr() as *const c_char;
    let mut plaintext = ptr::null() as *const c_char;
    let mut plaintext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_rsa_private_decrypt(padding, prv_key, ciphertext, ciphertext_len,
                                      &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!plaintext.is_null());
    assert!(plaintext_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(plaintext as *const u8, plaintext_len).to_vec();
        lib::yaca_free(plaintext as *mut c_void);
    };
    Ok(v)
}

/// Encrypts data using a RSA private key (low-level sign equivalent).
pub fn rsa_private_encrypt(padding: &Padding, prv_key: &Key, plaintext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let prv_key = key::get_handle(&prv_key);
    let plaintext_len: size_t = plaintext.len();
    let plaintext = plaintext.as_ptr() as *const c_char;
    let mut ciphertext = ptr::null() as *const c_char;
    let mut ciphertext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_rsa_private_encrypt(padding, prv_key, plaintext, plaintext_len,
                                      &mut ciphertext, &mut ciphertext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!ciphertext.is_null());
    assert!(ciphertext_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(ciphertext as *const u8, ciphertext_len).to_vec();
        lib::yaca_free(ciphertext as *mut c_void);
    };
    Ok(v)
}

/// Decrypts data using a RSA public key (low-level verify equivalent).
pub fn rsa_public_decrypt(padding: &Padding, pub_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>>
{
    let padding = conv::padding_rs_to_c(padding);
    let pub_key = key::get_handle(&pub_key);
    let ciphertext_len: size_t = ciphertext.len();
    let ciphertext = ciphertext.as_ptr() as *const c_char;
    let mut plaintext = ptr::null() as *const c_char;
    let mut plaintext_len: size_t = 0;
    let r = unsafe {
        lib::yaca_rsa_public_decrypt(padding, pub_key, ciphertext, ciphertext_len,
                                      &mut plaintext, &mut plaintext_len)
    };
    conv::res_c_to_rs(r)?;
    assert!(!plaintext.is_null());
    assert!(plaintext_len > 0);
    let v;
    unsafe {
        v = slice::from_raw_parts(plaintext as *const u8, plaintext_len).to_vec();
        lib::yaca_free(plaintext as *mut c_void);
    };
    Ok(v)
}
