use yaca::flat::*;

mod common;


#[test]
fn test_rsa_flat()
{
    // prepare:
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
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
