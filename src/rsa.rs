use libc::c_char;
use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;
use crate::yaca_conv as conv;
use crate::*;


/// Encrypts data using a RSA public key (low-level encrypt equivalent).
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
    let v = common::vector_from_raw(ciphertext_len, ciphertext);
    Ok(v)
}

/// Decrypts data using a RSA private key (low-level decrypt equivalent).
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
    let v = common::vector_from_raw(plaintext_len, plaintext);
    Ok(v)
}

/// Encrypts data using a RSA private key (low-level sign equivalent).
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
    let v = common::vector_from_raw(ciphertext_len, ciphertext);
    Ok(v)
}

/// Decrypts data using a RSA public key (low-level verify equivalent).
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
    let v = common::vector_from_raw(plaintext_len, plaintext);
    Ok(v)
}
