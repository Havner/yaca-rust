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
fn test_rsa()
{
    // prepare:
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let msg_short_max = 2048 / 8 - 11;
    let msg_short = &common::MSG[..msg_short_max];

    let enc_rsa = rsa_public_encrypt(&Padding::Pkcs1, &key_rsa_pub, msg_short).unwrap();
    let dec_rsa = rsa_private_decrypt(&Padding::Pkcs1, &key_rsa_prv, &enc_rsa).unwrap();

    assert_eq!(dec_rsa, msg_short.to_vec());

    let enc_rsa = rsa_private_encrypt(&Padding::Pkcs1, &key_rsa_prv, msg_short).unwrap();
    let dec_rsa = rsa_public_decrypt(&Padding::Pkcs1, &key_rsa_pub, &enc_rsa).unwrap();

    assert_eq!(dec_rsa, msg_short.to_vec());
}
