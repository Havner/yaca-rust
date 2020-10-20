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
fn sign()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    let hmac_simple = simple_calculate_hmac(&DigestAlgorithm::Sha512,
                                            &key_sym, common::MSG).unwrap();
    let cmac_simple = simple_calculate_cmac(&EncryptAlgorithm::Aes,
                                            &key_sym, common::MSG).unwrap();
    let sign_simple = simple_calculate_signature(&DigestAlgorithm::Sha512,
                                                 &key_rsa_prv, common::MSG).unwrap();
    // end prepare

    let ctx = SignContext::initialize_hmac(&DigestAlgorithm::Sha512, &key_sym).unwrap();
    for part in common::MSG.chunks(5) {
        ctx.update(part).unwrap();
    }
    let hmac = ctx.finalize().unwrap();

    assert_eq!(hmac, hmac_simple);

    let ctx = SignContext::initialize_cmac(&EncryptAlgorithm::Aes, &key_sym).unwrap();
    for part in common::MSG.chunks(5) {
        ctx.update(part).unwrap();
    }
    let cmac = ctx.finalize().unwrap();

    assert_eq!(cmac, cmac_simple);

    let ctx = SignContext::initialize(&DigestAlgorithm::Sha512, &key_rsa_prv).unwrap();
    for part in common::MSG.chunks(5) {
        ctx.update(part).unwrap();
    }
    let sig = ctx.finalize().unwrap();

    assert_eq!(sig, sign_simple);  // won't work for DSA

    let ctx = VerifyContext::initialize(&DigestAlgorithm::Sha512, &key_rsa_pub).unwrap();
    for part in common::MSG.chunks(7) {
        ctx.update(part).unwrap();
    }
    assert!(ctx.finalize(&sig).unwrap());

    // sign + set padding

    let ctx = SignContext::initialize(&DigestAlgorithm::Sha256, &key_rsa_prv).unwrap();
    for part in common::MSG.chunks(5) {
        ctx.update(part).unwrap();
    }
    ctx.set_property_padding(&Padding::Pkcs1Pss).unwrap();
    let sig = ctx.finalize().unwrap();

    let ctx = VerifyContext::initialize(&DigestAlgorithm::Sha256, &key_rsa_pub).unwrap();
    for part in common::MSG.chunks(7) {
        ctx.update(part).unwrap();
    }
    ctx.set_property_padding(&Padding::Pkcs1Pss).unwrap();
    assert!(ctx.finalize(&sig).unwrap());
}
