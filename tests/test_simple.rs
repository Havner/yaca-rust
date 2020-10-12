use yaca::*;

mod common;


#[test]
fn simple()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = Key::generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    let key_rsa_prv = Key::generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
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
