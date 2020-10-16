use libc::{c_int, size_t};

use crate::*;


const BASE_ERROR_YACA:              c_int = -0x01E30000;
const YACA_ERROR_NONE:              c_int = 0;
const YACA_ERROR_INVALID_PARAMETER: c_int = -22;
const YACA_ERROR_OUT_OF_MEMORY:     c_int = -12;
const YACA_ERROR_INTERNAL:          c_int = BASE_ERROR_YACA | 0x01;
const YACA_ERROR_DATA_MISMATCH:     c_int = BASE_ERROR_YACA | 0x02;
const YACA_ERROR_INVALID_PASSWORD:  c_int = BASE_ERROR_YACA | 0x03;

pub(crate) fn res_c_to_rs(r: c_int) -> crate::Result<()>
{
    match r {
        YACA_ERROR_NONE => Result::Ok(()),
        YACA_ERROR_INVALID_PARAMETER => Result::Err(Error::InvalidParameter),
        YACA_ERROR_OUT_OF_MEMORY => Result::Err(Error::OutOfMemory),
        YACA_ERROR_INTERNAL => Result::Err(Error::Internal),
        YACA_ERROR_DATA_MISMATCH => Result::Err(Error::DataMismatch),
        YACA_ERROR_INVALID_PASSWORD => Result::Err(Error::InvalidPassword),
        x => Result::Err(Error::Unknown(x)),
    }
}

pub(crate) fn res_c_to_rs_bool(r: c_int) -> crate::Result<bool>
{
    match r {
        YACA_ERROR_NONE => Result::Ok(true),
        YACA_ERROR_INVALID_PARAMETER => Result::Err(Error::InvalidParameter),
        YACA_ERROR_OUT_OF_MEMORY => Result::Err(Error::OutOfMemory),
        YACA_ERROR_INTERNAL => Result::Err(Error::Internal),
        YACA_ERROR_DATA_MISMATCH => Result::Ok(false),
        YACA_ERROR_INVALID_PASSWORD => Result::Err(Error::InvalidPassword),
        x => Result::Err(Error::Unknown(x)),
    }
}

const YACA_KEY_TYPE_SYMMETRIC:  c_int = 0;
const YACA_KEY_TYPE_DES:        c_int = 1;
const YACA_KEY_TYPE_IV:         c_int = 2;
const YACA_KEY_TYPE_RSA_PUB:    c_int = 3;
const YACA_KEY_TYPE_RSA_PRIV:   c_int = 4;
const YACA_KEY_TYPE_DSA_PUB:    c_int = 5;
const YACA_KEY_TYPE_DSA_PRIV:   c_int = 6;
const YACA_KEY_TYPE_DH_PUB:     c_int = 7;
const YACA_KEY_TYPE_DH_PRIV:    c_int = 8;
const YACA_KEY_TYPE_EC_PUB:     c_int = 9;
const YACA_KEY_TYPE_EC_PRIV:    c_int = 10;
const YACA_KEY_TYPE_DSA_PARAMS: c_int = 11;
const YACA_KEY_TYPE_DH_PARAMS:  c_int = 12;
const YACA_KEY_TYPE_EC_PARAMS:  c_int = 13;


pub(crate) fn key_type_rs_to_c(kt: &KeyType) -> c_int
{
    match kt {
        KeyType::Symmetric => YACA_KEY_TYPE_SYMMETRIC,
        KeyType::Des => YACA_KEY_TYPE_DES,
        KeyType::Iv => YACA_KEY_TYPE_IV,
        KeyType::Rsa(KeySubType::Public) => YACA_KEY_TYPE_RSA_PUB,
        KeyType::Rsa(KeySubType::Private) => YACA_KEY_TYPE_RSA_PRIV,
        KeyType::Dsa(KeySubType::Public) => YACA_KEY_TYPE_DSA_PUB,
        KeyType::Dsa(KeySubType::Private) => YACA_KEY_TYPE_DSA_PRIV,
        KeyType::Dh(KeySubType::Public) => YACA_KEY_TYPE_DH_PUB,
        KeyType::Dh(KeySubType::Private) => YACA_KEY_TYPE_DH_PRIV,
        KeyType::Ec(KeySubType::Public) => YACA_KEY_TYPE_EC_PUB,
        KeyType::Ec(KeySubType::Private) => YACA_KEY_TYPE_EC_PRIV,
        KeyType::Rsa(KeySubType::Params) => panic!("No KeySubType::Params for RSA"),
        KeyType::Dsa(KeySubType::Params) => YACA_KEY_TYPE_DSA_PARAMS,
        KeyType::Dh(KeySubType::Params) => YACA_KEY_TYPE_DH_PARAMS,
        KeyType::Ec(KeySubType::Params) => YACA_KEY_TYPE_EC_PARAMS,
    }
}

pub(crate) fn key_type_c_to_rs(kt: c_int) -> KeyType
{
    match kt {
        YACA_KEY_TYPE_SYMMETRIC => KeyType::Symmetric,
        YACA_KEY_TYPE_DES => KeyType::Des,
        YACA_KEY_TYPE_IV => KeyType::Iv,
        YACA_KEY_TYPE_RSA_PRIV => KeyType::Rsa(KeySubType::Private),
        YACA_KEY_TYPE_RSA_PUB => KeyType::Rsa(KeySubType::Public),
        YACA_KEY_TYPE_DSA_PRIV => KeyType::Dsa(KeySubType::Private),
        YACA_KEY_TYPE_DSA_PUB => KeyType::Dsa(KeySubType::Public),
        YACA_KEY_TYPE_DSA_PARAMS => KeyType::Dsa(KeySubType::Params),
        YACA_KEY_TYPE_EC_PRIV => KeyType::Ec(KeySubType::Private),
        YACA_KEY_TYPE_EC_PUB => KeyType::Ec(KeySubType::Public),
        YACA_KEY_TYPE_EC_PARAMS => KeyType::Ec(KeySubType::Params),
        YACA_KEY_TYPE_DH_PRIV => KeyType::Dh(KeySubType::Private),
        YACA_KEY_TYPE_DH_PUB => KeyType::Dh(KeySubType::Public),
        YACA_KEY_TYPE_DH_PARAMS => KeyType::Dh(KeySubType::Params),
        x => panic!("Wrong key_type passed from C: {}", x),
    }
}

const YACA_KEY_LENGTH_EC_PRIME192V1: c_int = 0x300000C0;
const YACA_KEY_LENGTH_EC_PRIME256V1: c_int = 0x30000100;
const YACA_KEY_LENGTH_EC_SECP256K1:  c_int = 0x31200100;
const YACA_KEY_LENGTH_EC_SECP384R1:  c_int = 0x31100180;
const YACA_KEY_LENGTH_EC_SECP521R1:  c_int = 0x31100209;

const YACA_KEY_LENGTH_DH_RFC_1024_160: c_int = 0x20000400;
const YACA_KEY_LENGTH_DH_RFC_2048_224: c_int = 0x21000800;
const YACA_KEY_LENGTH_DH_RFC_2048_256: c_int = 0x22000800;

const YACA_KEY_LENGTH_DH_GENERATOR_2: c_int = 0x10000000;
const YACA_KEY_LENGTH_DH_GENERATOR_5: c_int = 0x11000000;

pub(crate) fn key_length_rs_to_c(kl: &KeyLength) -> size_t
{
    match kl {
        KeyLength::Bits(bl) => *bl as size_t,
        KeyLength::Ec(KeyLengthEc::Prime192V1) => YACA_KEY_LENGTH_EC_PRIME192V1 as size_t,
        KeyLength::Ec(KeyLengthEc::Prime256V1) => YACA_KEY_LENGTH_EC_PRIME256V1 as size_t,
        KeyLength::Ec(KeyLengthEc::Secp256K1) => YACA_KEY_LENGTH_EC_SECP256K1 as size_t,
        KeyLength::Ec(KeyLengthEc::Secp384R1) => YACA_KEY_LENGTH_EC_SECP384R1 as size_t,
        KeyLength::Ec(KeyLengthEc::Secp521R1) => YACA_KEY_LENGTH_EC_SECP521R1 as size_t,
        KeyLength::Dh(KeyLengthDh::Rfc1024_160) => YACA_KEY_LENGTH_DH_RFC_1024_160 as size_t,
        KeyLength::Dh(KeyLengthDh::Rfc2048_224) => YACA_KEY_LENGTH_DH_RFC_2048_224 as size_t,
        KeyLength::Dh(KeyLengthDh::Rfc2048_256) => YACA_KEY_LENGTH_DH_RFC_2048_256 as size_t,
        KeyLength::Dh(KeyLengthDh::Generator2Bits(bl)) =>
            (YACA_KEY_LENGTH_DH_GENERATOR_2 as size_t | *bl as size_t),
        KeyLength::Dh(KeyLengthDh::Generator5Bits(bl)) =>
            (YACA_KEY_LENGTH_DH_GENERATOR_5 as size_t | *bl as size_t),
    }
}

pub(crate) fn key_length_c_to_rs(kl: size_t) -> KeyLength
{
    const MAX_BITS: c_int = std::u16::MAX as c_int;
    match kl as c_int {
        bl @ 0..=MAX_BITS => KeyLength::Bits(bl as u16),
        YACA_KEY_LENGTH_EC_PRIME192V1 => KeyLength::Ec(KeyLengthEc::Prime192V1),
        YACA_KEY_LENGTH_EC_PRIME256V1 => KeyLength::Ec(KeyLengthEc::Prime256V1),
        YACA_KEY_LENGTH_EC_SECP256K1 => KeyLength::Ec(KeyLengthEc::Secp256K1),
        YACA_KEY_LENGTH_EC_SECP384R1 => KeyLength::Ec(KeyLengthEc::Secp384R1),
        YACA_KEY_LENGTH_EC_SECP521R1 => KeyLength::Ec(KeyLengthEc::Secp521R1),
        x => panic!("Wrong key_bit_length passed from C: {}", x),
    }
}


// TODO: investigate, maybe it's better to do repr(C) for those enums
// instead of those conversions, those below should be 1:1 with C

const YACA_KEY_FORMAT_DEFAULT: c_int = 0;
const YACA_KEY_FORMAT_PKCS8:   c_int = 1;

pub(crate) fn key_format_rs_to_c(kf: &KeyFormat) -> c_int
{
    match kf {
        KeyFormat::Default => YACA_KEY_FORMAT_DEFAULT,
        KeyFormat::Pkcs8 => YACA_KEY_FORMAT_PKCS8,
    }
}

const YACA_KEY_FILE_FORMAT_RAW:    c_int = 0;
const YACA_KEY_FILE_FORMAT_BASE64: c_int = 1;
const YACA_KEY_FILE_FORMAT_PEM:    c_int = 2;
const YACA_KEY_FILE_FORMAT_DER:    c_int = 3;

pub(crate) fn key_file_format_rs_to_c(kff: &KeyFileFormat) -> c_int
{
    match kff {
        KeyFileFormat::Raw => YACA_KEY_FILE_FORMAT_RAW,
        KeyFileFormat::Base64 => YACA_KEY_FILE_FORMAT_BASE64,
        KeyFileFormat::Pem => YACA_KEY_FILE_FORMAT_PEM,
        KeyFileFormat::Der => YACA_KEY_FILE_FORMAT_DER,
    }
}

const YACA_DIGEST_MD5:    c_int = 0;
const YACA_DIGEST_SHA1:   c_int = 1;
const YACA_DIGEST_SHA224: c_int = 2;
const YACA_DIGEST_SHA256: c_int = 3;
const YACA_DIGEST_SHA384: c_int = 4;
const YACA_DIGEST_SHA512: c_int = 5;

pub(crate) fn digest_rs_to_c(digest: &DigestAlgorithm) -> c_int
{
    match digest {
        DigestAlgorithm::Md5 => YACA_DIGEST_MD5,
        DigestAlgorithm::Sha1 => YACA_DIGEST_SHA1,
        DigestAlgorithm::Sha224 => YACA_DIGEST_SHA224,
        DigestAlgorithm::Sha256 => YACA_DIGEST_SHA256,
        DigestAlgorithm::Sha384 => YACA_DIGEST_SHA384,
        DigestAlgorithm::Sha512 => YACA_DIGEST_SHA512,
    }
}

const YACA_ENCRYPT_AES:               c_int = 0;
const YACA_ENCRYPT_UNSAFE_DES:        c_int = 1;
const YACA_ENCRYPT_UNSAFE_3DES_2TDEA: c_int = 2;
const YACA_ENCRYPT_3DES_3TDEA:        c_int = 3;
const YACA_ENCRYPT_UNSAFE_RC2:        c_int = 4;
const YACA_ENCRYPT_UNSAFE_RC4:        c_int = 5;
const YACA_ENCRYPT_CAST5:             c_int = 6;

pub(crate) fn encrypt_rs_to_c(encrypt: &EncryptAlgorithm) -> c_int
{
    match encrypt {
        EncryptAlgorithm::Aes => YACA_ENCRYPT_AES,
        EncryptAlgorithm::UnsafeDes => YACA_ENCRYPT_UNSAFE_DES,
        EncryptAlgorithm::UnsafeTrippleDes2Tdea => YACA_ENCRYPT_UNSAFE_3DES_2TDEA,
        EncryptAlgorithm::TrippleDes3Tdea => YACA_ENCRYPT_3DES_3TDEA,
        EncryptAlgorithm::UnsafeRc2 => YACA_ENCRYPT_UNSAFE_RC2,
        EncryptAlgorithm::UnsafeRc4 => YACA_ENCRYPT_UNSAFE_RC4,
        EncryptAlgorithm::Cast5 => YACA_ENCRYPT_CAST5,
    }
}

const YACA_BCM_NONE: c_int = 0;
const YACA_BCM_ECB:  c_int = 1;
const YACA_BCM_CTR:  c_int = 2;
const YACA_BCM_CBC:  c_int = 3;
const YACA_BCM_GCM:  c_int = 4;
const YACA_BCM_CFB:  c_int = 5;
const YACA_BCM_CFB1: c_int = 6;
const YACA_BCM_CFB8: c_int = 7;
const YACA_BCM_OFB:  c_int = 8;
const YACA_BCM_CCM:  c_int = 9;
const YACA_BCM_WRAP: c_int = 10;

pub(crate) fn bcm_rs_to_c(bcm: &BlockCipherMode) -> c_int
{
    match bcm {
        BlockCipherMode::None => YACA_BCM_NONE,
        BlockCipherMode::Ecb => YACA_BCM_ECB,
        BlockCipherMode::Ctr => YACA_BCM_CTR,
        BlockCipherMode::Cbc => YACA_BCM_CBC,
        BlockCipherMode::Gcm => YACA_BCM_GCM,
        BlockCipherMode::Cfb => YACA_BCM_CFB,
        BlockCipherMode::Cfb1 => YACA_BCM_CFB1,
        BlockCipherMode::Cfb8 => YACA_BCM_CFB8,
        BlockCipherMode::Ofb => YACA_BCM_OFB,
        BlockCipherMode::Ccm => YACA_BCM_CCM,
        BlockCipherMode::Wrap => YACA_BCM_WRAP,
    }
}

const YACA_PROPERTY_PADDING:                c_int = 0;
const YACA_PROPERTY_GCM_AAD:                c_int = 1;
const YACA_PROPERTY_GCM_TAG:                c_int = 2;
const YACA_PROPERTY_GCM_TAG_LEN:            c_int = 3;
const YACA_PROPERTY_CCM_AAD:                c_int = 4;
const YACA_PROPERTY_CCM_TAG:                c_int = 5;
const YACA_PROPERTY_CCM_TAG_LEN:            c_int = 6;
const YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS: c_int = 7;

pub(crate) fn property_rs_to_c(prop: &types::Property) -> c_int
{
    match prop {
        types::Property::Padding => YACA_PROPERTY_PADDING,
        types::Property::GcmAad => YACA_PROPERTY_GCM_AAD,
        types::Property::GcmTag => YACA_PROPERTY_GCM_TAG,
        types::Property::GcmTagLen => YACA_PROPERTY_GCM_TAG_LEN,
        types::Property::CcmAad => YACA_PROPERTY_CCM_AAD,
        types::Property::CcmTag => YACA_PROPERTY_CCM_TAG,
        types::Property::CcmTagLen => YACA_PROPERTY_CCM_TAG_LEN,
        types::Property::Rc2EffectiveKeyBits => YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
    }
}

const YACA_PADDING_NONE:         c_int = 0;
const YACA_PADDING_X931:         c_int = 1;
const YACA_PADDING_PKCS1:        c_int = 2;
const YACA_PADDING_PKCS1_PSS:    c_int = 3;
const YACA_PADDING_PKCS1_OAEP:   c_int = 4;
const YACA_PADDING_PKCS1_SSLV23: c_int = 5;
const YACA_PADDING_PKCS7:        c_int = 6;

pub(crate) fn padding_rs_to_c(pad: &Padding) -> c_int
{
    match pad {
        Padding::None => YACA_PADDING_NONE,
        Padding::X931 => YACA_PADDING_X931,
        Padding::Pkcs1 => YACA_PADDING_PKCS1,
        Padding::Pkcs1Pss => YACA_PADDING_PKCS1_PSS,
        Padding::Pkcs1Oaep => YACA_PADDING_PKCS1_OAEP,
        Padding::Pkcs1SslV23 => YACA_PADDING_PKCS1_SSLV23,
        Padding::Pkcs7 => YACA_PADDING_PKCS7,
    }
}

const YACA_KDF_X942: c_int = 0;
const YACA_KDF_X962: c_int = 1;

pub(crate) fn kdf_rs_to_c(kdf: &Kdf) -> c_int
{
    match kdf {
        Kdf::X942 => YACA_KDF_X942,
        Kdf::X962 => YACA_KDF_X962,
    }
}
