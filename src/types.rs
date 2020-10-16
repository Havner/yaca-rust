use std::error;
use std::fmt;


#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidParameter,
    OutOfMemory,
    Internal,
    DataMismatch,
    InvalidPassword,
    Unknown(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self {
            Error::InvalidParameter => write!(f, "InvalidParameter"),
            Error::OutOfMemory => write!(f, "OutOfMemory"),
            Error::Internal => write!(f, "Internal"),
            Error::DataMismatch => write!(f, "DataMismatch"),
            Error::InvalidPassword => write!(f, "InvalidPassword"),
            Error::Unknown(e) => write!(f, "Unknown: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)>
    {
        Some(self)
    }
}

#[derive(Debug, PartialEq)]
pub enum KeyFormat {
    Default,
    Pkcs8,
}

#[derive(Debug, PartialEq)]
pub enum KeyFileFormat {
    Raw,
    Base64,
    Pem,
    Der,
}

#[derive(Debug, PartialEq)]
pub enum KeyType {
    Symmetric,
    Des,
    Iv,
    Rsa(KeySubType),
    Dsa(KeySubType),
    Ec(KeySubType),
    Dh(KeySubType),
}

#[derive(Debug, PartialEq)]
pub enum KeySubType {
    Private,
    Public,
    Params,
}

#[derive(Debug, PartialEq)]
pub enum KeyLength {
    Bits(u16),
    Ec(KeyLengthEc),
    Dh(KeyLengthDh),
}

#[derive(Debug, PartialEq)]
pub enum KeyLengthEc {
    Prime192V1,
    Prime256V1,
    Secp256K1,
    Secp384R1,
    Secp521R1,
}

#[derive(Debug, PartialEq)]
pub enum KeyLengthDh {
    Rfc1024_160,
    Rfc2048_224,
    Rfc2048_256,
    Generator2Bits(u16),
    Generator5Bits(u16),
}

#[derive(Debug, PartialEq)]
pub enum DigestAlgorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, PartialEq)]
pub enum EncryptAlgorithm {
	Aes,
	UnsafeDes,
	UnsafeTrippleDes2Tdea,
	TrippleDes3Tdea,
	UnsafeRc2,
	UnsafeRc4,
	Cast5,
}

#[derive(Debug, PartialEq)]
pub enum BlockCipherMode {
	None,
	Ecb,
	Ctr,
	Cbc,
	Gcm,
	Cfb,
	Cfb1,
	Cfb8,
	Ofb,
	Ccm,
	Wrap,
}

// Used by Context property functions
#[derive(Debug, PartialEq)]
pub(crate) enum Property {
	Padding,
	GcmAad,
	GcmTag,
	GcmTagLen,
	CcmAad,
	CcmTag,
	CcmTagLen,
	Rc2EffectiveKeyBits,
}

#[derive(Debug, PartialEq)]
pub enum Padding {
	None,
	X931,
	Pkcs1,
	Pkcs1Pss,
	Pkcs1Oaep,
	Pkcs1SslV23,
	Pkcs7,
}

#[derive(Debug, PartialEq)]
pub enum Kdf {
    X942,
    X962,
}
