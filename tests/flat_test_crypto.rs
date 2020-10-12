use yaca::flat::*;

mod common;


#[test]
fn crypto_flat()
{
    let vec1 = common::MSG.to_vec();
    assert_eq!(memcmp(common::MSG, &vec1, common::MSG.len()).unwrap(), true);

    let vec2: Vec<u8> = common::MSG.into_iter().map(|c| c.to_ascii_uppercase()).collect();
    assert_eq!(memcmp(common::MSG, &vec2, common::MSG.len()).unwrap(), false);

    let len: usize = 100;
    let rand_bytes1 = random_bytes(len).unwrap();
    assert_eq!(rand_bytes1.len(), len);
    let rand_bytes2 = random_bytes(len).unwrap();
    assert_eq!(rand_bytes2.len(), len);

    assert_eq!(memcmp(&rand_bytes1, &rand_bytes2, len).unwrap(), false);
}
