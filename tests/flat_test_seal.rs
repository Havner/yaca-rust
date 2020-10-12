use yaca::flat::*;

mod common;


#[test]
fn seal_basic_flat()
{
    // prepare:
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    // end prepare

    let (ctx, key_seal, iv) = seal_initialize(&key_rsa_pub,
                                              &EncryptAlgorithm::Aes,
                                              &BlockCipherMode::Cbc,
                                              &KeyLength::Bits(256)).unwrap();
    context_set_property_padding(&ctx, &Padding::Pkcs7).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut seal_update(&ctx, part).unwrap());
    }
    sealed.append(&mut seal_finalize(&ctx).unwrap());

    let ctx = open_initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                              &BlockCipherMode::Cbc, &KeyLength::Bits(256),
                              &key_seal, iv.as_ref()).unwrap();
    context_set_property_padding(&ctx, &Padding::Pkcs7).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut open_update(&ctx, part).unwrap());
    }
    opened.append(&mut open_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}

#[test]
fn seal_rc2_property_flat()
{
    // prepare:
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    // end prepare

    let (ctx, key_seal, iv) = seal_initialize(&key_rsa_pub,
                                              &EncryptAlgorithm::UnsafeRc2,
                                              &BlockCipherMode::Ecb,
                                              &KeyLength::Bits(256)).unwrap();
    assert!(iv.is_none());

    context_set_property_rc2_effective_key_bits(&ctx, 192).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut seal_update(&ctx, part).unwrap());
    }
    sealed.append(&mut seal_finalize(&ctx).unwrap());

    let ctx = open_initialize(&key_rsa_prv, &EncryptAlgorithm::UnsafeRc2,
                              &BlockCipherMode::Ecb, &KeyLength::Bits(256),
                              &key_seal, iv.as_ref()).unwrap();
    context_set_property_rc2_effective_key_bits(&ctx, 192).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut open_update(&ctx, part).unwrap());
    }
    opened.append(&mut open_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}

#[test]
fn encrypt_gcm_property_flat()
{
    // prepare:
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    // end prepare

    let tag_len = 16;
    let aad = random_bytes(16).unwrap();
    let (ctx, key_seal, iv) = seal_initialize(&key_rsa_pub,
                                              &EncryptAlgorithm::Aes,
                                              &BlockCipherMode::Gcm,
                                              &KeyLength::Bits(256)).unwrap();
    context_set_property_gcm_aad(&ctx, &aad).unwrap();
    let mut sealed: Vec<u8> = Vec::new();
    for part in common::MSG.chunks(5) {
        sealed.append(&mut seal_update(&ctx, part).unwrap());
    }
    sealed.append(&mut seal_finalize(&ctx).unwrap());
    context_set_property_gcm_tag_len(&ctx, tag_len).unwrap();
    let tag = context_get_property_gcm_tag(&ctx).unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = open_initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                              &BlockCipherMode::Gcm, &KeyLength::Bits(256),
                              &key_seal, iv.as_ref()).unwrap();
    context_set_property_gcm_aad(&ctx, &aad).unwrap();
    let mut opened: Vec<u8> = Vec::new();
    for part in sealed.chunks(7) {
        opened.append(&mut open_update(&ctx, part).unwrap());
    }
    context_set_property_gcm_tag(&ctx, &tag).unwrap();
    opened.append(&mut open_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}

#[test]
fn encrypt_ccm_property()
{
    // prepare:
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    // end prepare

    let tag_len = 12;
    let aad = random_bytes(16).unwrap();
    let (ctx, key_seal, iv) = seal_initialize(&key_rsa_pub,
                                              &EncryptAlgorithm::Aes,
                                              &BlockCipherMode::Ccm,
                                              &KeyLength::Bits(256)).unwrap();
    context_set_property_ccm_tag_len(&ctx, tag_len).unwrap();
    seal_set_input_length(&ctx, common::MSG.len()).unwrap();
    context_set_property_ccm_aad(&ctx, &aad).unwrap();

    let mut sealed: Vec<u8> = Vec::new();
    sealed.append(&mut seal_update(&ctx, common::MSG).unwrap());
    sealed.append(&mut seal_finalize(&ctx).unwrap());
    let tag = context_get_property_ccm_tag(&ctx).unwrap();
    assert_eq!(tag.len(), tag_len);

    let ctx = open_initialize(&key_rsa_prv, &EncryptAlgorithm::Aes,
                              &BlockCipherMode::Ccm, &KeyLength::Bits(256),
                              &key_seal, iv.as_ref()).unwrap();
    context_set_property_ccm_tag(&ctx, &tag).unwrap();
    open_set_input_length(&ctx, sealed.len()).unwrap();
    context_set_property_ccm_aad(&ctx, &aad).unwrap();

    let mut opened: Vec<u8> = Vec::new();
    opened.append(&mut open_update(&ctx, &sealed).unwrap());
    opened.append(&mut open_finalize(&ctx).unwrap());

    assert_eq!(common::MSG.to_vec(), opened);
}
