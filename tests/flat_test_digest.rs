use yaca::flat::*;

mod common;


#[test]
fn digest_flat()
{
    // prepare:
    let dgst_simple = simple_calculate_digest(&DigestAlgorithm::Sha512,
                                              common::MSG).unwrap();
    // end prepare

    let ctx = digest_initialize(&DigestAlgorithm::Sha512).unwrap();
    for part in common::MSG.chunks(5) {
        digest_update(&ctx, part).unwrap();
    }
    let dgst = digest_finalize(&ctx).unwrap();

    assert_eq!(dgst, dgst_simple);
}
