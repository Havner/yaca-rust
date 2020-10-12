use yaca::*;

mod common;


#[test]
fn sign()
{
    // prepare:
    let key_sym = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256)).unwrap();
    let key_rsa_prv = Key::generate(&KeyType::Rsa(Private), &KeyLength::Bits(2048)).unwrap();
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

    // SIGN + SET PADDING

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
