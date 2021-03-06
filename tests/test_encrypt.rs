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

use yaca::*;

mod common;


#[test]
fn encrypt_basic()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = Key::generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    let enc_simple = simple_encrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                    &key_sym, Some(&key_iv_128), common::MSG).unwrap();
    // end prepare

    let len_iv = EncryptContext::get_iv_length(&EncryptAlgorithm::Aes,
                                               &BlockCipherMode::Cbc,
                                               &KeyLength::Bits(256)).unwrap();

    match len_iv {
        Some(KeyLength::Bits(iv_bit_len)) => assert_eq!(iv_bit_len, 128),
        _ => panic!("IV bit length was expected, wrong or None returned"),
    }

    let ctx = EncryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                         &key_sym, Some(&key_iv_128)).unwrap();
    ctx.set_property_padding(&Padding::Pkcs7).unwrap();
    let mut enc: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        enc.append(&mut ctx.update(part).unwrap());
    }
    enc.append(&mut ctx.finalize().unwrap());

    assert_eq!(enc_simple, enc);

    let ctx = DecryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                         &key_sym, Some(&key_iv_128)).unwrap();
    ctx.set_property_padding(&Padding::Pkcs7).unwrap();
    let mut dec: Vec<u8> = Vec::new();
    for part in enc.chunks(7) {
        dec.append(&mut ctx.update(part).unwrap());
    }
    dec.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}

#[test]
fn encrypt_rc2_property()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    // end prepare

    let len_iv = EncryptContext::get_iv_length(&EncryptAlgorithm::UnsafeRc2,
                                               &BlockCipherMode::Ecb,
                                               &KeyLength::Bits(256)).unwrap();
    assert_eq!(len_iv, None);

    let ctx = EncryptContext::initialize(&EncryptAlgorithm::UnsafeRc2, &BlockCipherMode::Ecb,
                                         &key_sym, None).unwrap();
    ctx.set_property_rc2_effective_key_bits(192).unwrap();
    let mut enc: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        enc.append(&mut ctx.update(part).unwrap());
    }
    enc.append(&mut ctx.finalize().unwrap());

    let ctx = DecryptContext::initialize(&EncryptAlgorithm::UnsafeRc2, &BlockCipherMode::Ecb,
                                         &key_sym, None).unwrap();
    ctx.set_property_rc2_effective_key_bits(192).unwrap();
    let mut dec: Vec<u8> = Vec::new();
    for part in enc.chunks(7) {
        dec.append(&mut ctx.update(part).unwrap());
    }
    dec.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}

#[test]
fn encrypt_gcm_property()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = Key::generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    // end prepare

    let tag_len = 16;
    let aad = random_bytes(16).unwrap();
    let ctx = EncryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Gcm,
                                         &key_sym, Some(&key_iv_128)).unwrap();
    ctx.set_property_gcm_aad(&aad).unwrap();
    let mut enc: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        enc.append(&mut ctx.update(part).unwrap());
    }
    enc.append(&mut ctx.finalize().unwrap());
    ctx.set_property_gcm_tag_len(tag_len).unwrap();
    let tag = ctx.get_property_gcm_tag().unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = DecryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Gcm,
                                         &key_sym, Some(&key_iv_128)).unwrap();
    ctx.set_property_gcm_aad(&aad).unwrap();
    let mut dec: Vec<u8> = Vec::new();
    for part in enc.chunks(7) {
        dec.append(&mut ctx.update(part).unwrap());
    }
    ctx.set_property_gcm_tag(&tag).unwrap();
    dec.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}

#[test]
fn encrypt_ccm_property()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_64 = Key::generate(&KeyType::Iv, &KeyLength::Bits(64)).unwrap();
    // end prepare

    let tag_len = 12;
    let aad = random_bytes(16).unwrap();
    let ctx = EncryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Ccm,
                                         &key_sym, Some(&key_iv_64)).unwrap();
    ctx.set_property_ccm_tag_len(tag_len).unwrap();
    ctx.set_property_ccm_aad(&aad, common::MSG.len()).unwrap();

    let mut enc: Vec<u8> = Vec::new();
    enc.append(&mut ctx.update(common::MSG).unwrap());
    enc.append(&mut ctx.finalize().unwrap());
    let tag = ctx.get_property_ccm_tag().unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = DecryptContext::initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Ccm,
                                         &key_sym, Some(&key_iv_64)).unwrap();
    ctx.set_property_ccm_tag(&tag).unwrap();
    ctx.set_property_ccm_aad(&aad, enc.len()).unwrap();

    let mut dec: Vec<u8> = Vec::new();
    dec.append(&mut ctx.update(&enc).unwrap());
    dec.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}
