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
fn simple()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = Key::generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    let key_rsa_prv = Key::generate(&KeyType::RsaPrivate, &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    // end prepare

    let enc_simple = simple_encrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                    &key_sym, Some(&key_iv_128), common::MSG).unwrap();
    let dec_simple = simple_decrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                    &key_sym, Some(&key_iv_128), &enc_simple).unwrap();
    assert_eq!(common::MSG, dec_simple);

    let dgst_simple = simple_calculate_digest(&DigestAlgorithm::Sha512,
                                              common::MSG).unwrap();
    assert_eq!(dgst_simple.len(), 64);

    let hmac_simple = simple_calculate_hmac(&DigestAlgorithm::Sha512, &key_sym,
                                            common::MSG).unwrap();
    assert_eq!(hmac_simple.len(), 64);

    let cmac_simple = simple_calculate_cmac(&EncryptAlgorithm::Aes, &key_sym,
                                            common::MSG).unwrap();
    assert_eq!(cmac_simple.len(), 16);

    let sig_simple = simple_calculate_signature(&DigestAlgorithm::Sha512,
                                                &key_rsa_prv,
                                                common::MSG).unwrap();
    assert!(simple_verify_signature(&DigestAlgorithm::Sha512,
                                    &key_rsa_pub, common::MSG,
                                    &sig_simple).unwrap());
}
