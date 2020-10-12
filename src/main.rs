use std::ffi::CString;
use yaca::{self, Key, KeyType, KeyLength, KeyFormat, KeyFileFormat, Private, EncryptAlgorithm, BlockCipherMode, EncryptContext, DecryptContext};

use yaca::{prelude::*, Padding};


pub const MSG: &[u8] = b"Lorem ipsum dolor sit amet, consectetuer
adipiscing elit. Donec hendrerit tempor tellus. Donec pretium posuere
tellus. Proin quam nisl, tincidunt et, mattis eget, convallis nec,
purus. Cum sociis natoque penatibus et magnis dis parturient montes,
nascetur ridiculus mus. Nulla posuere. Donec vitae dolor. Nullam
tristique diam non turpis. Cras placerat accumsan nulla. Nullam
rutrum. Nam vestibulum accumsan nisl.";


fn main() -> Result<(), Box<dyn std::error::Error>>
{
    // Start

    yaca::initialize()?;

    // Keys

    let key = Key::generate(&KeyType::Rsa(Private),
                            &KeyLength::Bits(512))?;
    let p = CString::new("dupa")?;
    let data = key.export(&KeyFormat::Default, &KeyFileFormat::Pem, Some(&p))?;
    let key = Key::import(&data, &KeyType::Rsa(Private), Some(&p))?;

    println!("{:?}", key);

    // Simple encrypt/decrypt empty

    let sym_key = Key::generate(&KeyType::Symmetric, &KeyLength::Bits(256))?;
    let v = yaca::simple_encrypt(&EncryptAlgorithm::UnsafeRc4, &BlockCipherMode::None,
                                 &sym_key, None, &Vec::new())?;
    assert!(v.is_empty());
    let v = yaca::simple_decrypt(&EncryptAlgorithm::UnsafeRc4, &BlockCipherMode::None,
                                 &sym_key, None, &Vec::new())?;
    assert!(v.is_empty());

    // Simple encrypt/decrypt

    let iv = Key::generate(&KeyType::Iv, &KeyLength::Bits(128))?;
    let text = CString::new("test")?;
    let cipher = yaca::simple_encrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                      &sym_key, Some(&iv), text.to_bytes())?;
    let plain = yaca::simple_decrypt(&EncryptAlgorithm::Aes, &BlockCipherMode::Cbc,
                                     &sym_key, Some(&iv), &cipher)?;
    let plain = CString::new(plain)?;
    assert_eq!(text, plain);
    println!("{}", plain.to_str()?);

    // Prepare

    let algo = EncryptAlgorithm::Aes;
    let cbc = BlockCipherMode::Cbc;
    let key_len = KeyLength::Bits(256);
    let sym_key = Key::generate(&KeyType::Symmetric, &key_len)?;
    let iv_len = EncryptContext::get_iv_length(&algo, &cbc, &key_len)?;
    let iv = match &iv_len {
        None => None,
        Some(x) => Some(Key::generate(&KeyType::Iv, x)?),
    };
    if let Some(x) = &iv { println!("IV_used: {:?}", x); };

    // Encrypt

    let ctx = EncryptContext::initialize(&algo, &cbc, &sym_key, iv.as_ref())?;
    ctx.set_property_padding(&Padding::Pkcs7)?;
    let mut cipher: Vec<u8> = Vec::new();
    for i in MSG.chunks(5) {
        cipher.append(&mut ctx.update(i)?);
    };
    cipher.append(&mut ctx.finalize()?);

    // Decrypt

    let ctx = DecryptContext::initialize(&algo, &cbc, &sym_key, iv.as_ref())?;
    ctx.set_property_padding(&Padding::Pkcs7)?;
    let mut plain: Vec<u8> = Vec::new();
    for i in cipher.chunks(5) {
        plain.append(&mut ctx.update(i)?);
    };
    plain.append(&mut ctx.finalize()?);

    // Check

    assert_eq!(MSG, plain);
    let plain = CString::new(plain)?;
    println!("{}", plain.to_str()?);

    // Finish

    Ok(yaca::cleanup())
}
