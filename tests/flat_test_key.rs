use std::ffi::CString;
use yaca::flat::*;


#[test]
fn key_gen_flat()
{
    let key_iv_64 = key_generate(&KeyType::Iv, &KeyLength::Bits(64)).unwrap();
    assert_eq!(key_get_type(&key_iv_64).unwrap(), KeyType::Iv);
    assert_eq!(key_get_length(&key_iv_64).unwrap(), KeyLength::Bits(64));

    let key_iv_128 = key_generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    assert_eq!(key_get_type(&key_iv_128).unwrap(), KeyType::Iv);
    assert_eq!(key_get_length(&key_iv_128).unwrap(), KeyLength::Bits(128));

    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    assert_eq!(key_get_type(&key_sym).unwrap(), KeyType::Symmetric);
    assert_eq!(key_get_length(&key_sym).unwrap(), KeyLength::Bits(256));

    let key_rsa_prv = key_generate(&KeyType::Rsa(Private),
                                         &KeyLength::Bits(2048)).unwrap();
    assert_eq!(key_get_type(&key_rsa_prv).unwrap(), KeyType::Rsa(Private));
    assert_eq!(key_get_length(&key_rsa_prv).unwrap(), KeyLength::Bits(2048));

    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    assert_eq!(key_get_type(&key_rsa_pub).unwrap(), KeyType::Rsa(Public));
    assert_eq!(key_get_length(&key_rsa_pub).unwrap(), KeyLength::Bits(2048));

    let key_dsa_prv = key_generate(&KeyType::Dsa(Private),
                                         &KeyLength::Bits(2048)).unwrap();
    assert_eq!(key_get_type(&key_dsa_prv).unwrap(), KeyType::Dsa(Private));
    assert_eq!(key_get_length(&key_dsa_prv).unwrap(), KeyLength::Bits(2048));

    let key_dsa_pub = key_extract_public(&key_dsa_prv).unwrap();
    assert_eq!(key_get_type(&key_dsa_pub).unwrap(), KeyType::Dsa(Public));
    assert_eq!(key_get_length(&key_dsa_pub).unwrap(), KeyLength::Bits(2048));

    let key_dh_prv = key_generate(&KeyType::Dh(Private),
                                        &KeyLength::Dh(Rfc2048_256)).unwrap();
    assert_eq!(key_get_type(&key_dh_prv).unwrap(), KeyType::Dh(Private));
    assert_eq!(key_get_length(&key_dh_prv).unwrap(), KeyLength::Bits(2048));

    let key_dh_pub = key_extract_public(&key_dh_prv).unwrap();
    assert_eq!(key_get_type(&key_dh_pub).unwrap(), KeyType::Dh(Public));
    assert_eq!(key_get_length(&key_dh_pub).unwrap(), KeyLength::Bits(2048));

    let key_dh_params = key_extract_parameters(&key_dh_prv).unwrap();
    let key_dh_prv_2 = key_generate_from_parameters(&key_dh_params).unwrap();
    assert_eq!(key_get_type(&key_dh_prv_2).unwrap(),
               key_get_type(&key_dh_prv).unwrap());
    assert_eq!(key_get_length(&key_dh_prv_2).unwrap(),
               key_get_length(&key_dh_prv).unwrap());

    let key_dh_prv_3 = key_generate(&KeyType::Dh(Private),
                                          &KeyLength::Dh(Generator5Bits(256))).unwrap();
    assert_eq!(key_get_type(&key_dh_prv_3).unwrap(), KeyType::Dh(Private));
    assert_eq!(key_get_length(&key_dh_prv_3).unwrap(), KeyLength::Bits(256));

    let key_ec_prv = key_generate(&KeyType::Ec(Private),
                                        &KeyLength::Ec(Prime256V1)).unwrap();
    assert_eq!(key_get_type(&key_ec_prv).unwrap(), KeyType::Ec(Private));
    assert_eq!(key_get_length(&key_ec_prv).unwrap(), KeyLength::Ec(Prime256V1));

    let key_ec_pub = key_extract_public(&key_ec_prv).unwrap();
    assert_eq!(key_get_type(&key_ec_pub).unwrap(), KeyType::Ec(Public));
    assert_eq!(key_get_length(&key_ec_pub).unwrap(), KeyLength::Ec(Prime256V1));
}

#[test]
fn key_exp_imp_flat()
{
    // prepare
    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private),
                                         &KeyLength::Bits(2048)).unwrap();
    let password = CString::new("password").unwrap();
    // end prepare

    let key_sym_exp = key_export(&key_sym, &KeyFormat::Default,
                                       &KeyFileFormat::Base64, None).unwrap();
    let key_sym_imp = key_import(&key_sym_exp, &KeyType::Symmetric, None).unwrap();
    assert_eq!(key_get_type(&key_sym).unwrap(),
               key_get_type(&key_sym_imp).unwrap());
    assert_eq!(key_get_length(&key_sym).unwrap(),
               key_get_length(&key_sym_imp).unwrap());

    let key_rsa_prv_exp = key_export(&key_rsa_prv, &KeyFormat::Default,
                                           &KeyFileFormat::Pem, None).unwrap();
    let key_rsa_prv_imp = key_import(&key_rsa_prv_exp, &KeyType::Rsa(Private),
                                           None).unwrap();
    assert_eq!(key_get_type(&key_rsa_prv).unwrap(),
               key_get_type(&key_rsa_prv_imp).unwrap());
    assert_eq!(key_get_length(&key_rsa_prv).unwrap(),
               key_get_length(&key_rsa_prv_imp).unwrap());

    let key_rsa_prv_exp = key_export(&key_rsa_prv, &KeyFormat::Pkcs8,
                                           &KeyFileFormat::Pem, Some(&password)).unwrap();
    let key_rsa_prv_imp = key_import(&key_rsa_prv_exp, &KeyType::Rsa(Private),
                                           Some(&password)).unwrap();
    assert_eq!(key_get_type(&key_rsa_prv).unwrap(),
               key_get_type(&key_rsa_prv_imp).unwrap());
    assert_eq!(key_get_length(&key_rsa_prv).unwrap(),
               key_get_length(&key_rsa_prv_imp).unwrap());
}

#[test]
fn key_derive_flat()
{
    // prepare:
    let key_dh_prv = key_generate(&KeyType::Dh(Private),
                                        &KeyLength::Dh(Rfc2048_256)).unwrap();
    let key_dh_pub = key_extract_public(&key_dh_prv).unwrap();
    let key_dh_params = key_extract_parameters(&key_dh_prv).unwrap();
    let key_dh_prv_2 = key_generate_from_parameters(&key_dh_params).unwrap();
    let key_dh_pub_2 = key_extract_public(&key_dh_prv_2).unwrap();
    let password = CString::new("password").unwrap();
    // end prepare

    let secret = key_derive_dh(&key_dh_prv_2, &key_dh_pub).unwrap();
    assert_eq!(secret.len(), 256);

    let secret_2 = key_derive_dh(&key_dh_prv, &key_dh_pub_2).unwrap();
    assert_eq!(secret, secret_2);

    let key_material = key_derive_kdf(&Kdf::X942, &DigestAlgorithm::Sha256,
                                            &secret, None, 128).unwrap();
    assert_eq!(key_material.len(), 128);

    let key_derived = key_derive_pbkdf2(&password, None, 50000,
                                              &DigestAlgorithm::Sha256, 256).unwrap();
    assert_eq!(key_get_type(&key_derived).unwrap(), KeyType::Symmetric);
    assert_eq!(key_get_length(&key_derived).unwrap(), KeyLength::Bits(256));
}
