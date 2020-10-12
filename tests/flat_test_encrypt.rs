use yaca::flat::*;

mod common;


#[test]
fn encrypt_basic_flat()
{
    // prepare:
    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = key_generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    let enc_simple = simple_encrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                    &key_sym, Some(&key_iv_128), common::MSG).unwrap();
    // end prepare

    let len_iv = encrypt_get_iv_length(&EncryptAlgorithm::Aes,
                                       &BlockCipherMode::Cbc,
                                       &KeyLength::Bits(256)).unwrap();

    if let Some(KeyLength::Bits(iv_bit_len)) = len_iv {
        assert_eq!(iv_bit_len, 128);
    } else {
        panic!("Wrong IV bit length");
    }

    let ctx = encrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                 &key_sym, Some(&key_iv_128)).unwrap();
    context_set_property_padding(&ctx, &Padding::Pkcs7).unwrap();
    let mut enc: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        enc.append(&mut encrypt_update(&ctx, part).unwrap());
    }
    enc.append(&mut encrypt_finalize(&ctx).unwrap());

    assert_eq!(enc_simple, enc);

    let ctx = decrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                 &key_sym, Some(&key_iv_128)).unwrap();
    context_set_property_padding(&ctx, &Padding::Pkcs7).unwrap();
    let mut dec: Vec<u8> = Vec::new();
    for part in enc.chunks(7) {
        dec.append(&mut decrypt_update(&ctx, part).unwrap());
    }
    dec.append(&mut decrypt_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}

#[test]
fn encrypt_gcm_property_flat()
{
    // prepare:
    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_128 = key_generate(&KeyType::Iv, &KeyLength::Bits(128)).unwrap();
    // end prepare

    let tag_len = 16;
    let aad = random_bytes(16).unwrap();
    let ctx = encrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Gcm,
                                 &key_sym, Some(&key_iv_128)).unwrap();
    context_set_property_gcm_aad(&ctx, &aad).unwrap();
    let mut enc: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        enc.append(&mut encrypt_update(&ctx, part).unwrap());
    }
    enc.append(&mut encrypt_finalize(&ctx).unwrap());
    context_set_property_gcm_tag_len(&ctx, tag_len).unwrap();
    let tag = context_get_property_gcm_tag(&ctx).unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = decrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Gcm,
                                 &key_sym, Some(&key_iv_128)).unwrap();
    context_set_property_gcm_aad(&ctx, &aad).unwrap();
    let mut dec: Vec<u8> = Vec::new();
    for part in enc.chunks(7) {
        dec.append(&mut decrypt_update(&ctx, part).unwrap());
    }
    context_set_property_gcm_tag(&ctx, &tag).unwrap();
    dec.append(&mut decrypt_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}

#[test]
fn encrypt_ccm_property_flat()
{
    // prepare:
    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_iv_64 = key_generate(&KeyType::Iv, &KeyLength::Bits(64)).unwrap();
    // end prepare

    let tag_len = 12;
    let aad = random_bytes(16).unwrap();
    let ctx = encrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Ccm,
                                 &key_sym, Some(&key_iv_64)).unwrap();
    context_set_property_ccm_tag_len(&ctx, tag_len).unwrap();
    encrypt_set_input_length(&ctx, common::MSG.len()).unwrap();
    context_set_property_ccm_aad(&ctx, &aad).unwrap();

    let mut enc: Vec<u8> = Vec::new();
    enc.append(&mut encrypt_update(&ctx, common::MSG).unwrap());
    enc.append(&mut encrypt_finalize(&ctx).unwrap());
    let tag = context_get_property_ccm_tag(&ctx).unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = decrypt_initialize(&EncryptAlgorithm::Aes, &BlockCipherMode::Ccm,
                                 &key_sym, Some(&key_iv_64)).unwrap();
    context_set_property_ccm_tag(&ctx, &tag).unwrap();
    decrypt_set_input_length(&ctx, enc.len()).unwrap();
    context_set_property_ccm_aad(&ctx, &aad).unwrap();

    let mut dec: Vec<u8> = Vec::new();
    dec.append(&mut decrypt_update(&ctx, &enc).unwrap());
    dec.append(&mut decrypt_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), dec);
}
