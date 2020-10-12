use yaca::flat::*;

mod common;


#[test]
fn sign_flat()
{
    // prepare:
    let key_sym = key_generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_rsa_prv = key_generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
    let key_rsa_pub = key_extract_public(&key_rsa_prv).unwrap();
    let hmac_simple = simple_calculate_hmac(&DigestAlgorithm::Sha512,
                                            &key_sym, common::MSG).unwrap();
    let cmac_simple = simple_calculate_cmac(&EncryptAlgorithm::Aes,
                                            &key_sym, common::MSG).unwrap();
    let sign_simple = simple_calculate_signature(&DigestAlgorithm::Sha512,
                                                 &key_rsa_prv, common::MSG).unwrap();
    // end prepare

    let ctx = sign_initialize_hmac(&DigestAlgorithm::Sha512, &key_sym).unwrap();
    for part in common::MSG.chunks(5) {
        sign_update(&ctx, part).unwrap();
    }
    let hmac = sign_finalize(&ctx).unwrap();

    assert_eq!(hmac, hmac_simple);

    let ctx = sign_initialize_cmac(&EncryptAlgorithm::Aes, &key_sym).unwrap();
    for part in common::MSG.chunks(5) {
        sign_update(&ctx, part).unwrap();
    }
    let cmac = sign_finalize(&ctx).unwrap();

    assert_eq!(cmac, cmac_simple);

    let ctx = sign_initialize(&DigestAlgorithm::Sha512, &key_rsa_prv).unwrap();
    for part in common::MSG.chunks(5) {
        sign_update(&ctx, part).unwrap();
    }
    let sig = sign_finalize(&ctx).unwrap();

    assert_eq!(sig, sign_simple);  // won't work for DSA

    let ctx = verify_initialize(&DigestAlgorithm::Sha512, &key_rsa_pub).unwrap();
    for part in common::MSG.chunks(7) {
        verify_update(&ctx, part).unwrap();
    }
    assert!(verify_finalize(&ctx, &sig).unwrap());

    // SIGN + SET PADDING

    let ctx = sign_initialize(&DigestAlgorithm::Sha256, &key_rsa_prv).unwrap();
    for part in common::MSG.chunks(5) {
        sign_update(&ctx, part).unwrap();
    }
    context_set_property_padding(&ctx, &Padding::Pkcs1Pss).unwrap();
    let sig = sign_finalize(&ctx).unwrap();

    let ctx = verify_initialize(&DigestAlgorithm::Sha256, &key_rsa_pub).unwrap();
    for part in common::MSG.chunks(7) {
        verify_update(&ctx, part).unwrap();
    }
    context_set_property_padding(&ctx, &Padding::Pkcs1Pss).unwrap();
    assert!(verify_finalize(&ctx, &sig).unwrap());
}
