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

use std::ffi::CString;
use yaca::{self, prelude::*};
use yaca::{Key, KeyType, KeyLength, KeyFormat, KeyFileFormat, EncryptContext,
           DecryptContext, EncryptAlgorithm, BlockCipherMode, Padding};

pub const MSG: &[u8] = b"Lorem ipsum dolor sit amet, consectetuer
adipiscing elit. Donec hendrerit tempor tellus. Donec pretium posuere
tellus. Proin quam nisl, tincidunt et, mattis eget, convallis nec,
purus. Cum sociis natoque penatibus et magnis dis parturient montes,
nascetur ridiculus mus. Nulla posuere. Donec vitae dolor. Nullam
tristique diam non turpis. Cras placerat accumsan nulla. Nullam
rutrum. Nam vestibulum accumsan nisl.";

fn main() -> Result<(), Box<dyn std::error::Error>>
{
    // Start

    yaca::initialize()?;

    // Key generate/export/import example:

    let key = Key::generate(&KeyType::RsaPrivate,
                            &KeyLength::Bits(512))?;
    let p = CString::new("password")?;
    let data = key.export(&KeyFormat::Default, &KeyFileFormat::Pem, Some(&p))?;
    let key = Key::import(&data, &KeyType::RsaPrivate, Some(&p))?;

    println!("{:?}: {:?}", key.get_type()?, key.get_length()?);

    // Encrypt/decrypt example:

    // Prepare

    let algo = EncryptAlgorithm::Aes;
    let cbc = BlockCipherMode::Cbc;
    let key_len = KeyLength::Bits(256);
    let sym_key = Key::generate(&KeyType::Symmetric, &key_len)?;
    let iv_len = EncryptContext::get_iv_length(&algo, &cbc, &key_len)?;
    let iv = match &iv_len {
        None => None,
        Some(x) => Some(Key::generate(&KeyType::Iv, x)?),
    };
    if let Some(x) = &iv {
        println!("IV_used: {:?}: {:?}", x.get_type()?, x.get_length()?);
    };

    // Encrypt

    let ctx = EncryptContext::initialize(&algo, &cbc, &sym_key, iv.as_ref())?;
    ctx.set_property_padding(&Padding::Pkcs7)?;
    let mut cipher: Vec<u8> = Vec::new();
    for i in MSG.chunks(5) {
        cipher.append(&mut ctx.update(i)?);
    };
    cipher.append(&mut ctx.finalize()?);

    // Decrypt

    let ctx = DecryptContext::initialize(&algo, &cbc, &sym_key, iv.as_ref())?;
    ctx.set_property_padding(&Padding::Pkcs7)?;
    let mut plain: Vec<u8> = Vec::new();
    for i in cipher.chunks(5) {
        plain.append(&mut ctx.update(i)?);
    };
    plain.append(&mut ctx.finalize()?);

    // Check

    assert_eq!(MSG, plain);
    let plain = CString::new(plain)?;
    println!("{}", plain.to_str()?);

    // Simple encrypt/decrypt empty

    let sym_key = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256))?;
    let v = yaca::simple_encrypt(&EncryptAlgorithm::UnsafeRc4, &BlockCipherMode::None,
                                 &sym_key, None, &Vec::new())?;
    assert!(v.is_empty());
    let v = yaca::simple_decrypt(&EncryptAlgorithm::UnsafeRc4, &BlockCipherMode::None,
                                 &sym_key, None, &Vec::new())?;
    assert!(v.is_empty());

    // Simple encrypt/decrypt

    let iv = Key::generate(&KeyType::Iv, &KeyLength::Bits(128))?;
    let cipher = yaca::simple_encrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                      &sym_key, Some(&iv), MSG)?;
    let plain = yaca::simple_decrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                     &sym_key, Some(&iv), &cipher)?;

    // Check for simple

    assert_eq!(MSG, plain);
    let plain = CString::new(plain)?;
    println!("{}", plain.to_str()?);

    // Finish

    Ok(yaca::cleanup())
}
