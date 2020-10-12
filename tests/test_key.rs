use std::ffi::CString;
use yaca::*;


#[test]
fn key_gen()
{
    let key_iv_64 = Key::generate(&KeyType::Iv, &KeyLength::Bits(64)).unwrap();
    assert_eq!(key_iv_64.get_type().unwrap(), KeyType::Iv);
    assert_eq!(key_iv_64.get_length().unwrap(), KeyLength::Bits(64));

    let key_iv_128 = Key::generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    assert_eq!(key_iv_128.get_type().unwrap(), KeyType::Iv);
    assert_eq!(key_iv_128.get_length().unwrap(), KeyLength::Bits(128));

    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    assert_eq!(key_sym.get_type().unwrap(), KeyType::Symmetric);
    assert_eq!(key_sym.get_length().unwrap(), KeyLength::Bits(256));

    let key_rsa_prv = Key::generate(&KeyType::Rsa(Private),
                                    &KeyLength::Bits(2048)).unwrap();
    assert_eq!(key_rsa_prv.get_type().unwrap(), KeyType::Rsa(Private));
    assert_eq!(key_rsa_prv.get_length().unwrap(), KeyLength::Bits(2048));

    let key_rsa_pub = key_rsa_prv.extract_public().unwrap();
    assert_eq!(key_rsa_pub.get_type().unwrap(), KeyType::Rsa(Public));
    assert_eq!(key_rsa_pub.get_length().unwrap(), KeyLength::Bits(2048));

    let key_dsa_prv = Key::generate(&KeyType::Dsa(Private),
                                    &KeyLength::Bits(2048)).unwrap();
    assert_eq!(key_dsa_prv.get_type().unwrap(), KeyType::Dsa(Private));
    assert_eq!(key_dsa_prv.get_length().unwrap(), KeyLength::Bits(2048));

    let key_dsa_pub = key_dsa_prv.extract_public().unwrap();
    assert_eq!(key_dsa_pub.get_type().unwrap(), KeyType::Dsa(Public));
    assert_eq!(key_dsa_pub.get_length().unwrap(), KeyLength::Bits(2048));

    let key_dh_prv = Key::generate(&KeyType::Dh(Private),
                                   &KeyLength::Dh(Rfc2048_256)).unwrap();
    assert_eq!(key_dh_prv.get_type().unwrap(), KeyType::Dh(Private));
    assert_eq!(key_dh_prv.get_length().unwrap(), KeyLength::Bits(2048));

    let key_dh_pub = key_dh_prv.extract_public().unwrap();
    assert_eq!(key_dh_pub.get_type().unwrap(), KeyType::Dh(Public));
    assert_eq!(key_dh_pub.get_length().unwrap(), KeyLength::Bits(2048));

    let key_dh_params = key_dh_prv.extract_parameters().unwrap();
    let key_dh_prv_2 = Key::generate_from_parameters(&key_dh_params).unwrap();
    assert_eq!(key_dh_prv_2.get_type().unwrap(), key_dh_prv.get_type().unwrap());
    assert_eq!(key_dh_prv_2.get_length().unwrap(), key_dh_prv.get_length().unwrap());

    let key_dh_prv_3 = Key::generate(&KeyType::Dh(Private),
                                     &KeyLength::Dh(Generator5Bits(256))).unwrap();
    assert_eq!(key_dh_prv_3.get_type().unwrap(), KeyType::Dh(Private));
    assert_eq!(key_dh_prv_3.get_length().unwrap(), KeyLength::Bits(256));

    let key_ec_prv = Key::generate(&KeyType::Ec(Private),
                                   &KeyLength::Ec(Prime256V1)).unwrap();
    assert_eq!(key_ec_prv.get_type().unwrap(), KeyType::Ec(Private));
    assert_eq!(key_ec_prv.get_length().unwrap(), KeyLength::Ec(Prime256V1));

    let key_ec_pub = key_ec_prv.extract_public().unwrap();
    assert_eq!(key_ec_pub.get_type().unwrap(), KeyType::Ec(Public));
    assert_eq!(key_ec_pub.get_length().unwrap(), KeyLength::Ec(Prime256V1));
}

#[test]
fn key_exp_imp()
{
    // prepare
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_rsa_prv = Key::generate(&KeyType::Rsa(Private),
                                    &KeyLength::Bits(2048)).unwrap();
    let password = CString::new("password").unwrap();
    // end prepare

    let key_sym_exp = key_sym.export(&KeyFormat::Default,
                                     &KeyFileFormat::Base64, None).unwrap();
    let key_sym_imp = Key::import(&key_sym_exp, &KeyType::Symmetric, None).unwrap();
    assert_eq!(key_sym.get_type().unwrap(), key_sym_imp.get_type().unwrap());
    assert_eq!(key_sym.get_length().unwrap(), key_sym_imp.get_length().unwrap());

    let key_rsa_prv_exp = key_rsa_prv.export(&KeyFormat::Default,
                                             &KeyFileFormat::Pem, None).unwrap();
    let key_rsa_prv_imp = Key::import(&key_rsa_prv_exp, &KeyType::Rsa(Private),
                                      None).unwrap();
    assert_eq!(key_rsa_prv.get_type().unwrap(), key_rsa_prv_imp.get_type().unwrap());
    assert_eq!(key_rsa_prv.get_length().unwrap(), key_rsa_prv_imp.get_length().unwrap());

    let key_rsa_prv_exp = key_rsa_prv.export(&KeyFormat::Pkcs8,
                                             &KeyFileFormat::Pem, Some(&password)).unwrap();
    let key_rsa_prv_imp = Key::import(&key_rsa_prv_exp, &KeyType::Rsa(Private),
                                      Some(&password)).unwrap();
    assert_eq!(key_rsa_prv.get_type().unwrap(), key_rsa_prv_imp.get_type().unwrap());
    assert_eq!(key_rsa_prv.get_length().unwrap(), key_rsa_prv_imp.get_length().unwrap());
}

#[test]
fn key_derive()
{
    // prepare:
    let key_dh_prv = Key::generate(&KeyType::Dh(Private),
                                   &KeyLength::Dh(Rfc2048_256)).unwrap();
    let key_dh_pub = key_dh_prv.extract_public().unwrap();
    let key_dh_params = key_dh_prv.extract_parameters().unwrap();
    let key_dh_prv_2 = Key::generate_from_parameters(&key_dh_params).unwrap();
    let key_dh_pub_2 = key_dh_prv_2.extract_public().unwrap();
    let password = CString::new("password").unwrap();
    // end prepare

    let secret = Key::derive_dh(&key_dh_prv_2, &key_dh_pub).unwrap();
    assert_eq!(secret.len(), 256);

    let secret_2 = Key::derive_dh(&key_dh_prv, &key_dh_pub_2).unwrap();
    assert_eq!(secret, secret_2);

    let key_material = Key::derive_kdf(&Kdf::X942, &DigestAlgorithm::Sha256,
                                       &secret, None, 128).unwrap();
    assert_eq!(key_material.len(), 128);

    let key_derived = Key::derive_pbkdf2(&password, None, 50000,
                                         &DigestAlgorithm::Sha256, 256).unwrap();
    assert_eq!(key_derived.get_type().unwrap(), KeyType::Symmetric);
    assert_eq!(key_derived.get_length().unwrap(), KeyLength::Bits(256));
}
