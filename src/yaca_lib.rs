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


// TODO: write a glue library in YACA to solve "enum is not
// necessarily an int" issue.

/// Bindings to the YACA library API in C.
#[link(name = "yaca")]
extern {
    // crypto
    pub fn yaca_initialize() -> c_int;
    pub fn yaca_cleanup();
    pub fn yaca_free(memory: *mut c_void);
    pub fn yaca_memcmp(first: *const c_void, second: *const c_void, len: size_t) -> c_int;
    pub fn yaca_randomize_bytes(data: *mut c_char, data_len: size_t) -> c_int;
    pub fn yaca_context_set_property(ctx: *mut c_void, property: c_int,
                                     value: *const c_void, value_len: size_t) -> c_int;
    pub fn yaca_context_get_property(ctx: *const c_void, property: c_int,
                                     value: *mut *const c_void, value_len: *mut size_t) -> c_int;
    pub fn yaca_context_get_output_length(ctx: *const c_void, input_len: size_t,
                                          output_len: *mut size_t) -> c_int;
    pub fn yaca_context_destroy(ctx: *mut c_void);

    // key
    pub fn yaca_key_get_type(key: *const c_void, key_type: *mut c_int) -> c_int;
    pub fn yaca_key_get_bit_length(key: *const c_void, key_bit_length: *mut size_t) -> c_int;
    pub fn yaca_key_import(key_type: c_int, password: *const c_char,
                           data: *const c_char, data_len: size_t,
                           key: *mut *const c_void) -> c_int;
    pub fn yaca_key_export(key: *const c_void, key_fmt: c_int, key_file_fmt: c_int,
                           password: *const c_char, data: *mut *const c_void,
                           data_len: *mut size_t) -> c_int;
    pub fn yaca_key_generate(key_type: c_int, key_bit_len: size_t,
                             key: *mut *const c_void) -> c_int;
    pub fn yaca_key_generate_from_parameters(params: *const c_void,
                                             prv_key: *mut *const c_void) -> c_int;
    pub fn yaca_key_extract_public(prv_key: *const c_void,
                                   pub_key: *mut *const c_void) -> c_int;
    pub fn yaca_key_extract_parameters(key: *const c_void,
                                       params: *mut *const c_void) -> c_int;
    pub fn yaca_key_derive_dh(prv_key: *const c_void, pub_key: *const c_void,
                              secret: *mut *const c_char, secret_len: *mut size_t) -> c_int;
    pub fn yaca_key_derive_kdf(kdf: c_int, algo: c_int,
                               secret: *const c_char, secret_len: size_t,
                               info: *const c_char, info_len: size_t,
                               key_material_len: size_t,
                               key_material: *mut *const c_char) -> c_int;
    pub fn yaca_key_derive_pbkdf2(password: *const c_char, salt: *const c_char,
                                  salt_len: size_t, iterations: size_t,
                                  algo: c_int, key_bit_len: size_t,
                                  key: *mut *const c_void) -> c_int;
    pub fn yaca_key_destroy(key: *mut c_void);

    // simple
    pub fn yaca_simple_encrypt(algo: c_int, bcm: c_int,
                               sym_key: *const c_void, iv: *const c_void,
                               plaintext: *const c_char, plaintext_len: size_t,
                               ciphertext: *mut *const c_char,
                               ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_simple_decrypt(algo: c_int, bcm: c_int,
                               sym_key: *const c_void, iv: *const c_void,
                               ciphertext: *const c_char, ciphertext_len: size_t,
                               plaintext: *mut *const c_char,
                               plaintext_len: *mut size_t) -> c_int;
    pub fn yaca_simple_calculate_digest(algo: c_int,
                                        message: *const c_char, message_len: size_t,
                                        digest: *mut *const c_char,
                                        digest_len: *mut size_t) -> c_int;
    pub fn yaca_simple_calculate_signature(algo: c_int, prv_key: *const c_void,
                                           message: *const c_char, message_len: size_t,
                                           signature: *mut *const c_char,
                                           signature_len: *mut size_t) -> c_int;
    pub fn yaca_simple_verify_signature(algo: c_int, pub_key: *const c_void,
                                        message: *const c_char, message_len: size_t,
                                        signature: *const c_char,
                                        signature_len: size_t) -> c_int;
    pub fn yaca_simple_calculate_hmac(algo: c_int, sym_key: *const c_void,
                                      message: *const c_char, message_len: size_t,
                                      mac: *mut *const c_char,
                                      mac_len: *mut size_t) -> c_int;
    pub fn yaca_simple_calculate_cmac(algo: c_int, sym_key: *const c_void,
                                      message: *const c_char, message_len: size_t,
                                      mac: *mut *const c_char,
                                      mac_len: *mut size_t) -> c_int;

    // digest
    pub fn yaca_digest_initialize(ctx: *mut *mut c_void, algo: c_int) -> c_int;
    pub fn yaca_digest_update(ctx: *mut c_void, message: *const c_char,
                              message_len: size_t) -> c_int;
    pub fn yaca_digest_finalize(ctx: *mut c_void, digest: *mut c_char,
                                digest_len: *mut size_t) -> c_int;

    // encrypt
    pub fn yaca_encrypt_get_iv_bit_length(algo: c_int, bcm: c_int, key_bit_len: size_t,
                                          iv_bit_len: *mut size_t) -> c_int;
    pub fn yaca_encrypt_initialize(ctx: *mut *mut c_void, algo: c_int, bcm: c_int,
                                   sym_key: *const c_void, iv: *const c_void) -> c_int;
    pub fn yaca_encrypt_update(ctx: *mut c_void, plaintext: *const c_char,
                               plaintext_len: size_t, ciphertext: *mut c_char,
                               ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_encrypt_finalize(ctx: *mut c_void, ciphertext: *mut c_char,
                                 ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_decrypt_initialize(ctx: *mut *mut c_void, algo: c_int, bcm: c_int,
                                   sym_key: *const c_void, iv: *const c_void) -> c_int;
    pub fn yaca_decrypt_update(ctx: *mut c_void, ciphertext: *const c_char,
                               ciphertext_len: size_t, plaintext: *mut c_char,
                               plaintext_len: *mut size_t) -> c_int;
    pub fn yaca_decrypt_finalize(ctx: *mut c_void, plaintext: *mut c_char,
                                 plaintext_len: *mut size_t) -> c_int;

    // seal
    pub fn yaca_seal_initialize(ctx: *mut *mut c_void, pub_key: *const c_void,
                                algo: c_int, bcm: c_int, sym_key_bit_len: size_t,
                                sym_key: *mut *const c_void, iv: *mut *const c_void) -> c_int;
    pub fn yaca_seal_update(ctx: *mut c_void, plaintext: *const c_char,
                            plaintext_len: size_t, ciphertext: *mut c_char,
                            ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_seal_finalize(ctx: *mut c_void, ciphertext: *mut c_char,
                              ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_open_initialize(ctx: *mut *mut c_void, prv_key: *const c_void,
                                algo: c_int, bcm: c_int, sym_key_bit_len: size_t,
                                sym_key: *const c_void, iv: *const c_void) -> c_int;
    pub fn yaca_open_update(ctx: *mut c_void, ciphertext: *const c_char,
                            ciphertext_len: size_t, plaintext: *mut c_char,
                            plaintext_len: *mut size_t) -> c_int;
    pub fn yaca_open_finalize(ctx: *mut c_void, plaintext: *mut c_char,
                              plaintext_len: *mut size_t) -> c_int;

    // rsa
    pub fn yaca_rsa_public_encrypt(padding: c_int, pub_key: *const c_void,
                                   plaintext: *const c_char, plaintext_len: size_t,
                                   ciphertext: *mut *const c_char,
                                   ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_rsa_private_decrypt(padding: c_int, prv_key: *const c_void,
                                    ciphertext: *const c_char, ciphertext_len: size_t,
                                    plaintext: *mut *const c_char,
                                    plaintext_len: *mut size_t) -> c_int;
    pub fn yaca_rsa_private_encrypt(padding: c_int, prv_key: *const c_void,
                                    plaintext: *const c_char, plaintext_len: size_t,
                                    ciphertext: *mut *const c_char,
                                    ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_rsa_public_decrypt(padding: c_int, pub_key: *const c_void,
                                   ciphertext: *const c_char, ciphertext_len: size_t,
                                   plaintext: *mut *const c_char,
                                   plaintext_len: *mut size_t) -> c_int;

    // sign
    pub fn yaca_sign_initialize(ctx: *mut *mut c_void, algo: c_int,
                                prv_key: *const c_void) -> c_int;
    pub fn yaca_sign_initialize_hmac(ctx: *mut *mut c_void, algo: c_int,
                                     sym_key: *const c_void) -> c_int;
    pub fn yaca_sign_initialize_cmac(ctx: *mut *mut c_void, algo: c_int,
                                     sym_key: *const c_void) -> c_int;
    pub fn yaca_sign_update(ctx: *mut c_void, message: *const c_char,
                            message_len: size_t) -> c_int;
    pub fn yaca_sign_finalize(ctx: *mut c_void,
                              signature: *mut c_char,
                              signature_len: *mut size_t) -> c_int;
    pub fn yaca_verify_initialize(ctx: *mut *mut c_void, algo: c_int,
                                  pub_key: *const c_void) -> c_int;
    pub fn yaca_verify_update(ctx: *mut c_void, message: *const c_char,
                              message_len: size_t) -> c_int;
    pub fn yaca_verify_finalize(ctx: *mut c_void, signature: *const c_char,
                                signature_len: size_t) -> c_int;
}
