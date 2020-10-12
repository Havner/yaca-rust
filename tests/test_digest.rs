use yaca::*;

mod common;


#[test]
fn digest()
{
    // prepare:
    let dgst_simple = simple_calculate_digest(&DigestAlgorithm::Sha512,
                                              common::MSG).unwrap();
    // end prepare

    let ctx = DigestContext::initialize(&DigestAlgorithm::Sha512).unwrap();
    for part in common::MSG.chunks(5) {
        ctx.update(part).unwrap();
    }
    let dgst = ctx.finalize().unwrap();

    assert_eq!(dgst, dgst_simple);
}
