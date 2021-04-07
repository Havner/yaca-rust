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

use std::convert::{TryFrom, TryInto};
use libc::{c_char, c_int, c_void, size_t};

// TODO: write a glue library in YACA to solve "enum is not
// necessarily an int" issue.


#[cfg_attr(not(feature="static"),
           link(name = "yaca"))]
#[cfg_attr(feature="static",
           link(name = "yaca", kind="static"),
           link(name = "crypto", kind="static"),
           link(name = "stdc++", kind="static-nobundle"))]
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

    // unsupported
    pub fn yaca_key_rsa_generate(key_bit_len: size_t, key_pub_exp: u64,
                                 key: *mut *const c_void) -> c_int;
    pub fn yaca_key_rsa_get_public_exponent(key: *const c_void,
                                            key_pub_exp: *mut u64) -> c_int;
    pub fn yaca_rsa_public_encrypt_2(padding: c_int, digest: c_int, pub_key: *const c_void,
                                     plaintext: *const c_char, plaintext_len: size_t,
                                     ciphertext: *mut *const c_char,
                                     ciphertext_len: *mut size_t) -> c_int;
    pub fn yaca_rsa_private_decrypt_2(padding: c_int, digest: c_int, prv_key: *const c_void,
                                      ciphertext: *const c_char, ciphertext_len: size_t,
                                      plaintext: *mut *const c_char,
                                      plaintext_len: *mut size_t) -> c_int;
    // unsupported keymaster
    pub fn build_wrapped_key(transit_key: *const u8, transit_key_size: size_t,
                             iv: *const u8, iv_size: size_t,
                             key_format: keymaster_key_format_t,
                             secure_key: *const u8, secure_key_size: size_t,
                             tag: *const u8, tag_size: size_t,
                             auth_data: *const keymaster_key_param_t, auth_data_size: size_t,
                             der: *mut *const u8, der_size: *mut size_t) -> keymaster_error_t;
    pub fn parse_wrapped_key(der: *const u8, der_size: size_t,
                             iv: *mut *const u8, iv_size: *mut size_t,
                             transit_key: *mut *const u8, transit_key_size: *mut size_t,
                             secure_key: *mut *const u8, secure_key_size: *mut size_t,
                             tag: *mut *const u8, tag_size: *mut size_t,
                             auth_data: *mut *const keymaster_key_param_t, auth_data_size: *mut size_t,
                             key_format: *mut keymaster_key_format_t,
                             der_desc: *mut *const u8, der_desc_size: *mut size_t) -> keymaster_error_t;
}

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum keymaster_tag_type_t {
    KmInvalid = 0 << 28, /* Invalid type, used to designate a tag as uninitialized */
    KmEnum = 1 << 28,
    KmEnumRep = 2 << 28, /* Repeatable enumeration value. */
    KmUint = 3 << 28,
    KmUintRep = 4 << 28, /* Repeatable integer value */
    KmUlong = 5 << 28,
    KmDate = 6 << 28,
    KmBool = 7 << 28,
    KmBignum = 8 << 28,
    KmBytes = 9 << 28,
    KmUlongRep = 10 << 28, /* Repeatable long value */
}

impl TryFrom<u32> for keymaster_tag_type_t {
    type Error = ();

    fn try_from(value: u32) -> Result<keymaster_tag_type_t, Self::Error>
    {
        match value {
            value if value == keymaster_tag_type_t::KmInvalid as u32 => Ok(keymaster_tag_type_t::KmInvalid),
            value if value == keymaster_tag_type_t::KmEnum as u32 => Ok(keymaster_tag_type_t::KmEnum),
            value if value == keymaster_tag_type_t::KmEnumRep as u32 => Ok(keymaster_tag_type_t::KmEnumRep),
            value if value == keymaster_tag_type_t::KmUint as u32 => Ok(keymaster_tag_type_t::KmUint),
            value if value == keymaster_tag_type_t::KmUintRep as u32 => Ok(keymaster_tag_type_t::KmUintRep),
            value if value == keymaster_tag_type_t::KmUlong as u32 => Ok(keymaster_tag_type_t::KmUlong),
            value if value == keymaster_tag_type_t::KmDate as u32 => Ok(keymaster_tag_type_t::KmDate),
            value if value == keymaster_tag_type_t::KmBool as u32 => Ok(keymaster_tag_type_t::KmBool),
            value if value == keymaster_tag_type_t::KmBignum as u32 => Ok(keymaster_tag_type_t::KmBignum),
            value if value == keymaster_tag_type_t::KmBytes as u32 => Ok(keymaster_tag_type_t::KmBytes),
            value if value == keymaster_tag_type_t::KmUlongRep as u32 => Ok(keymaster_tag_type_t::KmUlongRep),
            _ => Err(()),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum keymaster_tag_t {
    KmTagInvalid = keymaster_tag_type_t::KmInvalid as isize | 0,

    KmTagPurpose = keymaster_tag_type_t::KmEnumRep as isize | 1,
    KmTagAlgorithm = keymaster_tag_type_t::KmEnum as isize | 2,
    KmTagKeySize = keymaster_tag_type_t::KmUint as isize | 3,
    KmTagBlockMode = keymaster_tag_type_t::KmEnumRep as isize | 4,
    KmTagDigest = keymaster_tag_type_t::KmEnumRep as isize | 5,
    KmTagPadding = keymaster_tag_type_t::KmEnumRep as isize | 6,
    KmTagCallerNonce = keymaster_tag_type_t::KmBool as isize | 7,
    KmTagMinMacLength = keymaster_tag_type_t::KmUint as isize | 8,
    KmTagKdf = keymaster_tag_type_t::KmEnumRep as isize | 9,
    KmTagEcCurve = keymaster_tag_type_t::KmEnum as isize | 10,

    KmTagRsaPublicExponent = keymaster_tag_type_t::KmUlong as isize | 200,
    KmTagEciesSingleHashMode = keymaster_tag_type_t::KmBool as isize | 201,
    KmTagIncludeUniqueId = keymaster_tag_type_t::KmBool as isize | 202,
    KmTagRsaOaepMgfDigest = keymaster_tag_type_t::KmEnumRep as isize | 203,

    KmTagBlobUsageRequirements = keymaster_tag_type_t::KmEnum as isize | 301,
    KmTagBootloaderOnly = keymaster_tag_type_t::KmBool as isize | 302,
    KmTagRollbackResistance = keymaster_tag_type_t::KmBool as isize | 303,
    KmTagEarlyBootOnly = keymaster_tag_type_t::KmBool as isize | 305,

    KmTagActiveDatetime = keymaster_tag_type_t::KmDate as isize | 400,
    KmTagOriginationExpireDatetime = keymaster_tag_type_t::KmDate as isize | 401,
    KmTagUsageExpireDatetime = keymaster_tag_type_t::KmDate as isize | 402,
    KmTagMinSecondsBetweenOps = keymaster_tag_type_t::KmUint as isize | 403,
    KmTagMaxUsesPerBoot = keymaster_tag_type_t::KmUint as isize | 404,
    KmTagUsageCountLimit = keymaster_tag_type_t::KmUint as isize | 405,

    KmTagAllUsers = keymaster_tag_type_t::KmBool as isize | 500,
    KmTagUserId = keymaster_tag_type_t::KmUint as isize | 501,
    KmTagUserSecureId = keymaster_tag_type_t::KmUlongRep as isize | 502,
    KmTagNoAuthRequired = keymaster_tag_type_t::KmBool as isize | 503,
    KmTagUserAuthType = keymaster_tag_type_t::KmEnum as isize | 504,
    KmTagAuthTimeout = keymaster_tag_type_t::KmUint as isize | 505,
    KmTagAllowWhileOnBody = keymaster_tag_type_t::KmBool as isize | 506,
    KmTagTrustedUserPresenceRequired = keymaster_tag_type_t::KmBool as isize | 507,
    KmTagTrustedConfirmationRequired = keymaster_tag_type_t::KmBool as isize | 508,
    KmTagUnlockedDeviceRequired = keymaster_tag_type_t::KmBool as isize | 509,

    KmTagAllApplications = keymaster_tag_type_t::KmBool as isize | 600,
    KmTagApplicationId = keymaster_tag_type_t::KmBytes as isize | 601,
    KmTagExportable = keymaster_tag_type_t::KmBool as isize | 602,

    KmTagApplicationData = keymaster_tag_type_t::KmBytes as isize | 700,
    KmTagCreationDatetime = keymaster_tag_type_t::KmDate as isize | 701,
    KmTagOrigin = keymaster_tag_type_t::KmEnum as isize | 702,
    KmTagRollbackResistant = keymaster_tag_type_t::KmBool as isize | 703,
    KmTagRootOfTrust = keymaster_tag_type_t::KmBytes as isize | 704,
    KmTagOsVersion = keymaster_tag_type_t::KmUint as isize | 705,
    KmTagOsPatchlevel = keymaster_tag_type_t::KmUint as isize | 706,
    KmTagUniqueId = keymaster_tag_type_t::KmBytes as isize | 707,
    KmTagAttestationChallenge = keymaster_tag_type_t::KmBytes as isize | 708,
    KmTagAttestationApplicationId = keymaster_tag_type_t::KmBytes as isize | 709,
    KmTagAttestationIdBrand = keymaster_tag_type_t::KmBytes as isize | 710,
    KmTagAttestationIdDevice = keymaster_tag_type_t::KmBytes as isize | 711,
    KmTagAttestationIdProduct = keymaster_tag_type_t::KmBytes as isize | 712,
    KmTagAttestationIdSerial = keymaster_tag_type_t::KmBytes as isize | 713,
    KmTagAttestationIdImei = keymaster_tag_type_t::KmBytes as isize | 714,
    KmTagAttestationIdMeid = keymaster_tag_type_t::KmBytes as isize | 715,
    KmTagAttestationIdManufacturer = keymaster_tag_type_t::KmBytes as isize | 716,
    KmTagAttestationIdModel = keymaster_tag_type_t::KmBytes as isize | 717,
    KmTagVendorPatchlevel =  keymaster_tag_type_t::KmUint as isize | 718,
    KmTagBootPatchlevel =  keymaster_tag_type_t::KmUint as isize | 719,
    KmTagDeviceUniqueAttestation = keymaster_tag_type_t::KmBool as isize | 720,
    KmTagIdentityCredentialKey = keymaster_tag_type_t::KmBool as isize | 721,
    KmTagStorageKey = keymaster_tag_type_t::KmBool as isize | 722,

    KmTagAssociatedData = keymaster_tag_type_t::KmBytes as isize | 1000,
    KmTagNonce = keymaster_tag_type_t::KmBytes as isize | 1001,
    KmTagAuthToken = keymaster_tag_type_t::KmBytes as isize | 1002,
    KmTagMacLength = keymaster_tag_type_t::KmUint as isize | 1003,
    KmTagResetSinceIdRotation = keymaster_tag_type_t::KmBool as isize | 1004,
    KmTagConfirmationToken = keymaster_tag_type_t::KmBytes as isize | 1005,
    KmTagCertificateSerial = keymaster_tag_type_t::KmBignum as isize | 1006,
    KmTagCertificateSubject = keymaster_tag_type_t::KmBytes as isize | 1007,
    KmTagCertificateNotBefore = keymaster_tag_type_t::KmDate as isize | 1008,
    KmTagCertificateNotAfter = keymaster_tag_type_t::KmDate as isize | 1009,
    KmTagMaxBootLevel = keymaster_tag_type_t::KmUint as isize | 1010,
}

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum keymaster_key_format_t {
    KmKeyFormatX509 = 0,
    KmKeyFormatPkcs8 = 1,
    KmKeyFormatRaw = 3,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct keymaster_blob_t {
    pub data: *const u8,
    pub data_length: size_t,
}

#[repr(C)]
pub union keymaster_key_param_content_t {
    pub enumerated: u32,
    pub boolean: bool,
    pub integer: u32,
    pub long_integer: u64,
    pub date_time: u64,
    pub blob: keymaster_blob_t,
}

#[repr(C)]
pub struct keymaster_key_param_t {
    pub tag: keymaster_tag_t,
    pub content: keymaster_key_param_content_t,
}

impl std::clone::Clone for keymaster_key_param_t {
    fn clone(&self) -> Self {
        match keymaster_tag_get_type(&self.tag) {
            keymaster_tag_type_t::KmInvalid =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { boolean: false } },
            keymaster_tag_type_t::KmBool =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { boolean: unsafe { self.content.boolean } } },
            keymaster_tag_type_t::KmEnum | keymaster_tag_type_t::KmEnumRep =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { enumerated: unsafe { self.content.enumerated } } },
            keymaster_tag_type_t::KmUint | keymaster_tag_type_t::KmUintRep =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { integer: unsafe { self.content.integer } } },
            keymaster_tag_type_t::KmUlong | keymaster_tag_type_t::KmUlongRep =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { long_integer: unsafe { self.content.long_integer } } },
            keymaster_tag_type_t::KmDate =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { date_time: unsafe { self.content.date_time } } },
            keymaster_tag_type_t::KmBignum | keymaster_tag_type_t::KmBytes =>
                keymaster_key_param_t { tag: self.tag.clone(), content: keymaster_key_param_content_t { blob: unsafe { self.content.blob.clone() } } },
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum keymaster_error_t {
    KmErrorOk = 0,
    KmErrorRootOfTrustAlreadySet = -1,
    KmErrorUnsupportedPurpose = -2,
    KmErrorIncompatiblePurpose = -3,
    KmErrorUnsupportedAlgorithm = -4,
    KmErrorIncompatibleAlgorithm = -5,
    KmErrorUnsupportedKeySize = -6,
    KmErrorUnsupportedBlockMode = -7,
    KmErrorIncompatibleBlockMode = -8,
    KmErrorUnsupportedMacLength = -9,
    KmErrorUnsupportedPaddingMode = -10,
    KmErrorIncompatiblePaddingMode = -11,
    KmErrorUnsupportedDigest = -12,
    KmErrorIncompatibleDigest = -13,
    KmErrorInvalidExpirationTime = -14,
    KmErrorInvalidUserId = -15,
    KmErrorInvalidAuthorizationTimeout = -16,
    KmErrorUnsupportedKeyFormat = -17,
    KmErrorIncompatibleKeyFormat = -18,
    KmErrorUnsupportedKeyEncryptionAlgorithm = -19,   /* For PKCS8 & PKCS12 */
    KmErrorUnsupportedKeyVerificationAlgorithm = -20, /* For PKCS8 & PKCS12 */
    KmErrorInvalidInputLength = -21,
    KmErrorKeyExportOptionsInvalid = -22,
    KmErrorDelegationNotAllowed = -23,
    KmErrorKeyNotYetValid = -24,
    KmErrorKeyExpired = -25,
    KmErrorKeyUserNotAuthenticated = -26,
    KmErrorOutputParameterNull = -27,
    KmErrorInvalidOperationHandle = -28,
    KmErrorInsufficientBufferSpace = -29,
    KmErrorVerificationFailed = -30,
    KmErrorTooManyOperations = -31,
    KmErrorUnexpectedNullPointer = -32,
    KmErrorInvalidKeyBlob = -33,
    KmErrorImportedKeyNotEncrypted = -34,
    KmErrorImportedKeyDecryptionFailed = -35,
    KmErrorImportedKeyNotSigned = -36,
    KmErrorImportedKeyVerificationFailed = -37,
    KmErrorInvalidArgument = -38,
    KmErrorUnsupportedTag = -39,
    KmErrorInvalidTag = -40,
    KmErrorMemoryAllocationFailed = -41,
    KmErrorImportParameterMismatch = -44,
    KmErrorSecureHwAccessDenied = -45,
    KmErrorOperationCancelled = -46,
    KmErrorConcurrentAccessConflict = -47,
    KmErrorSecureHwBusy = -48,
    KmErrorSecureHwCommunicationFailed = -49,
    KmErrorUnsupportedEcField = -50,
    KmErrorMissingNonce = -51,
    KmErrorInvalidNonce = -52,
    KmErrorMissingMacLength = -53,
    KmErrorKeyRateLimitExceeded = -54,
    KmErrorCallerNonceProhibited = -55,
    KmErrorKeyMaxOpsExceeded = -56,
    KmErrorInvalidMacLength = -57,
    KmErrorMissingMinMacLength = -58,
    KmErrorUnsupportedMinMacLength = -59,
    KmErrorUnsupportedKdf = -60,
    KmErrorUnsupportedEcCurve = -61,
    KmErrorKeyRequiresUpgrade = -62,
    KmErrorAttestationChallengeMissing = -63,
    KmErrorKeymasterNotConfigured = -64,
    KmErrorAttestationApplicationIdMissing = -65,
    KmErrorCannotAttestIds = -66,
    KmErrorRollbackResistanceUnavailable = -67,
    KmErrorNoUserConfirmation = -71,
    KmErrorDeviceLocked = -72,
    KmErrorEarlyBootEnded = -73,
    KmErrorAttestationKeysNotProvisioned = -74,
    KmErrorAttestationIdsNotProvisioned = -75,
    KmErrorIncompatibleMgfDigest = -78,
    KmErrorUnsupportedMgfDigest = -79,
    KmErrorMissingNotBefore = -80,
    KmErrorMissingNotAfter = -81,
    KmErrorMissingIssuerSubject = -82,
    KmErrorInvalidIssuerSubject = -83,
    KmErrorBootLevelExceeded = -84,

    KmErrorUnimplemented = -100,
    KmErrorVersionMismatch = -101,

    KmErrorUnknownError = -1000,
}


/* Convenience functions for manipulating keymaster_key_param_t structs */

pub fn keymaster_tag_get_type(tag: &keymaster_tag_t) -> keymaster_tag_type_t {
    (tag.clone() as u32 & (0xF << 28)).try_into().unwrap()
}

pub fn keymaster_tag_mask_type(tag: &keymaster_tag_t) -> u32 {
    tag.clone() as u32 & 0x0FFFFFFF
}

pub fn keymaster_tag_type_repeatable(tag_type: &keymaster_tag_type_t) -> bool {
    match tag_type {
        keymaster_tag_type_t::KmUintRep | /* UlongRep ignored in the original impl */
        keymaster_tag_type_t::KmEnumRep => true,
        _ => false,
    }
}

pub fn keymaster_tag_repeatable(tag: &keymaster_tag_t) -> bool {
    keymaster_tag_type_repeatable(&keymaster_tag_get_type(tag))
}

// /* Convenience functions for manipulating key_param_t structs */

pub fn keymaster_param_enum(tag: keymaster_tag_t, value: u32) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        enumerated: value,
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

pub fn keymaster_param_int(tag: keymaster_tag_t, value: u32) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        integer: value,
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

pub fn keymaster_param_long(tag: keymaster_tag_t, value: u64) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        long_integer: value,
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

pub fn keymaster_param_blob(tag: keymaster_tag_t, bytes: &[u8]) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        blob: keymaster_blob_t {
            data: bytes.as_ptr(),
            data_length: bytes.len(),
        },
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

pub fn keymaster_param_bool(tag: keymaster_tag_t) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        boolean: true,
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

pub fn keymaster_param_date(tag: keymaster_tag_t, value: u64) -> keymaster_key_param_t {
    let content = keymaster_key_param_content_t {
        date_time: value,
    };
    keymaster_key_param_t {
        tag,
        content,
    }
}

/* call only on data returned from parse_wrapped_key() */
pub fn keymaster_free_param_values(data: &[keymaster_key_param_t]) {
    for p in data {
        match keymaster_tag_get_type(&p.tag) {
            keymaster_tag_type_t::KmBytes |
            keymaster_tag_type_t::KmBignum => {
                unsafe {
                    yaca_free(p.content.blob.data as *mut c_void);
                }
            }
            _ => ()
        }
    }
}
