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
fn seal_basic()
{
    // prepare:
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let (ctx, key_seal, iv) = SealContext::initialize(&key_rsa_pub,
                                                      &EncryptAlgorithm::Aes,
                                                      &BlockCipherMode::Cbc,
                                                      &KeyLength::Bits(256)).unwrap();
    ctx.set_property_padding(&Padding::Pkcs7).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut ctx.update(part).unwrap());
    }
    sealed.append(&mut ctx.finalize().unwrap());

    let ctx = OpenContext::initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                                      &BlockCipherMode::Cbc, &KeyLength::Bits(256),
                                      &key_seal, iv.as_ref()).unwrap();
    ctx.set_property_padding(&Padding::Pkcs7).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut ctx.update(part).unwrap());
    }
    opened.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}

#[test]
fn seal_rc2_property()
{
    // prepare:
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let (ctx, key_seal, iv) = SealContext::initialize(&key_rsa_pub,
                                                      &EncryptAlgorithm::UnsafeRc2,
                                                      &BlockCipherMode::Ecb,
                                                      &KeyLength::Bits(256)).unwrap();
    assert!(iv.is_none());

    ctx.set_property_rc2_effective_key_bits(192).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut ctx.update(part).unwrap());
    }
    sealed.append(&mut ctx.finalize().unwrap());

    let ctx = OpenContext::initialize(&key_rsa_prv, &EncryptAlgorithm::UnsafeRc2,
                                      &BlockCipherMode::Ecb, &KeyLength::Bits(256),
                                      &key_seal, iv.as_ref()).unwrap();
    ctx.set_property_rc2_effective_key_bits(192).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut ctx.update(part).unwrap());
    }
    opened.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}

#[test]
fn encrypt_gcm_property() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    // prepare:
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let tag_len = 16;
    let aad = random_bytes(16).unwrap();
    let (ctx, key_seal, iv) = SealContext::initialize(&key_rsa_pub,
                                                      &EncryptAlgorithm::Aes,
                                                      &BlockCipherMode::Gcm,
                                                      &KeyLength::Bits(256)).unwrap();
    ctx.set_property_gcm_aad(&aad).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut ctx.update(part).unwrap());
    }
    sealed.append(&mut ctx.finalize().unwrap());
    ctx.set_property_gcm_tag_len(tag_len).unwrap();
    let tag = ctx.get_property_gcm_tag().unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = OpenContext::initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                                      &BlockCipherMode::Gcm, &KeyLength::Bits(256),
                                      &key_seal, iv.as_ref()).unwrap();
    ctx.set_property_gcm_aad(&aad).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut ctx.update(part).unwrap());
    }
    ctx.set_property_gcm_tag(&tag).unwrap();
    opened.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), opened);

    Ok(())
}

#[test]
fn encrypt_ccm_property()
{
    // prepare:
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let tag_len = 12;
    let aad = random_bytes(16).unwrap();
    let (ctx, key_seal, iv) = SealContext::initialize(&key_rsa_pub,
                                                      &EncryptAlgorithm::Aes,
                                                      &BlockCipherMode::Ccm,
                                                      &KeyLength::Bits(256)).unwrap();
    ctx.set_property_ccm_tag_len(tag_len).unwrap();
    ctx.set_property_ccm_aad(&aad, common::MSG.len()).unwrap();

    let mut sealed: Vec<u8> = Vec::new();
    sealed.append(&mut ctx.update(common::MSG).unwrap());
    sealed.append(&mut ctx.finalize().unwrap());
    let tag = ctx.get_property_ccm_tag().unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = OpenContext::initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                                      &BlockCipherMode::Ccm, &KeyLength::Bits(256),
                                      &key_seal, iv.as_ref()).unwrap();
    ctx.set_property_ccm_tag(&tag).unwrap();
    ctx.set_property_ccm_aad(&aad, sealed.len()).unwrap();

    let mut opened: Vec<u8> = Vec::new();
    opened.append(&mut ctx.update(&sealed).unwrap());
    opened.append(&mut ctx.finalize().unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}
