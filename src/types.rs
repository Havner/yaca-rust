/*
 *  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */


/// Enumeration of YACA key formats
#[derive(Debug, PartialEq)]
pub enum KeyFormat {
    /// Key is either PKCS#1 for RSA or SSLeay for DSA, also use this option for symmetric
    Default,
    /// Key is in PKCS#8, can only be used for asymmetric private keys
    Pkcs8,
}

/// Enumeration of YACA key file formats
#[derive(Debug, PartialEq)]
pub enum KeyFileFormat {
    /// Key file is in raw binary format, used for symmetric keys
    Raw,
    /// Key file is encoded in ASCII-base64, used for symmetric keys
    Base64,
    /// Key file is in PEM file format, used for asymmetric keys
    Pem,
    /// Key file is in DER file format, used for asymmetric keys
    Der,
}

/// Enumeration of YACA key types, Initialization Vector is considered as key
#[derive(Debug, PartialEq)]
pub enum KeyType {
    /// Generic symmetric cipher KEY
    Symmetric,
    /// DES* key - must be handled differently because of parity bits
    Des,
    /// Initialization Vector for symmetric algorithms
    Iv,
    /// RSA private key
    RsaPrivate,
    /// RSA public key
    RsaPublic,
    /// Digital Signature Algorithm private key
    DsaPrivate,
    /// Digital Signature Algorithm public key
    DsaPublic,
    /// Digital Signature Algorithm parameters
    DsaParams,
    /// Elliptic Curve private key for DSA and DH
    EcPrivate,
    /// Elliptic Curve public key for DSA and DH
    EcPublic,
    /// Elliptic Curve parameters
    EcParams,
    /// Diffie-Hellman key private key
    DhPrivate,
    /// Diffie-Hellman key public key
    DhPublic,
    /// Diffie-Hellman key parameters
    DhParams,
}

/// Enumeration of YACA key lengths
///
/// - For [`KeyType`]s: [`Symmetric`], [`DES`], [`IV`], [`RSA`] and [`DSA`] use `Bits`.
/// - For [`EC`] use `Ec`.
/// - For [`DH`] use `Dh`.
///
/// [`KeyType`]: enum.KeyType.html
/// [`Symmetric`]: enum.KeyType.html#variant.Symmetric
/// [`DES`]: enum.KeyType.html#variant.Des
/// [`IV`]: enum.KeyType.html#variant.Iv
/// [`RSA`]: enum.KeyType.html#variant.RsaPrivate
/// [`DSA`]: enum.KeyType.html#variant.DsaPrivate
/// [`EC`]: enum.KeyType.html#variant.EcPrivate
/// [`DH`]: enum.KeyType.html#variant.DhPrivate
#[derive(Debug, PartialEq)]
pub enum KeyLength {
    /// Key length represented by number of bits
    ///
    /// - `bits` needs to be divisible by 8.
    Bits(u16),
    /// Specific key lengths for Elliptic Curve keys
    Ec(KeyLengthEc),
    /// Specific key lengths for Diffie-Hellman key
    Dh(KeyLengthDh),
}

/// Enumeration of YACA elliptic curve types with their bit lengths
///
/// - It's meant to be passed or returned with [`KeyLength::Ec`] in
///   appropriate functions when dealing with elliptic curves.
///
/// [`KeyLength::Ec`]: enum.KeyLength.html#variant.Ec
#[derive(Debug, PartialEq)]
pub enum KeyLengthEc {
    /// Elliptic curve prime192v1
    Prime192V1,
    /// Elliptic curve prime256v1
    Prime256V1,
    /// Elliptic curve secp256k1
    Secp256K1,
    /// Elliptic curve secp384r1
    Secp384R1,
    /// Elliptic curve secp521r1
    Secp521R1,
}

/// Enumeration of various YACA DH parameters including RFC 5114
///
/// - It's meant to be passed or returned with [`KeyLength::Dh`] in
///   appropriate functions when dealing with Diffie-Hellman.
///
/// [`KeyLength::Dh`]: enum.KeyLength.html#variant.Dh
#[derive(Debug, PartialEq)]
pub enum KeyLengthDh {
    /// RFC 5114 DH parameters 1024_160
    Rfc1024_160,
    /// RFC 5114 DH parameters 2048_224
    Rfc2048_224,
    /// RFC 5114 DH parameters 2048_256
    Rfc2048_256,
    /// Generator equal 2 for DH parameters
    ///
    /// - Needs specifying safe prime length in bits.
    /// - Prime length needs to be >= 256 and divisble by 8.
    /// - Prime length is recommended to be 2048 bits or higher.
    Generator2Bits(u16),
    /// Generator equal 5 for DH parameters
    ///
    /// - Needs specifying safe prime length in bits.
    /// - Prime length needs to be >= 256 and divisble by 8.
    /// - Prime length is recommended to be 2048 bits or higher.
    Generator5Bits(u16),
}

/// Enumeration of YACA message digest algorithms
#[derive(Debug, PartialEq)]
pub enum DigestAlgorithm {
    /// Message digest algorithm MD5
    Md5,
    /// Message digest algorithm SHA1
    Sha1,
    /// Message digest algorithm SHA2, 224bit
    Sha224,
    /// Message digest algorithm SHA2, 256bit
    Sha256,
    /// Message digest algorithm SHA2, 384bit
    Sha384,
    /// Message digest algorithm SHA2, 512bit
    Sha512,
}

/// Enumeration of YACA symmetric encryption algorithms
#[derive(Debug, PartialEq)]
pub enum EncryptAlgorithm {
    /// AES encryption
    ///
    /// - Supported key lengths: [`128`], [`192`] and [`256`] bits.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`CFB1`],
    ///   * [`CFB8`],
    ///   * [`ECB`],
    ///   * [`GCM`],
    ///   * [`CCM`],
    ///   * [`CTR`],
    ///   * [`Wrap`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    ///
    /// [`128`]: enum.KeyLength.html#variant.Bits
    /// [`192`]: enum.KeyLength.html#variant.Bits
    /// [`256`]: enum.KeyLength.html#variant.Bits
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`CFB1`]: enum.BlockCipherMode.html#variant.Cfb1
    /// [`CFB8`]: enum.BlockCipherMode.html#variant.Cfb8
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`GCM`]: enum.BlockCipherMode.html#variant.Gcm
    /// [`CCM`]: enum.BlockCipherMode.html#variant.Ccm
    /// [`CTR`]: enum.BlockCipherMode.html#variant.Ctr
    /// [`Wrap`]: enum.BlockCipherMode.html#variant.Wrap
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    Aes,

    /// DES encryption (unsafe)
    ///
    /// - Supported key lengths: [`64`] bits.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`CFB1`],
    ///   * [`CFB8`],
    ///   * [`ECB`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    ///
    /// [`64`]: enum.KeyLength.html#variant.Bits
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`CFB1`]: enum.BlockCipherMode.html#variant.Cfb1
    /// [`CFB8`]: enum.BlockCipherMode.html#variant.Cfb8
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    UnsafeDes,

    /// 3DES 2-key encryption (unsafe)
    ///
    /// - Supported key lengths: [`128`] bits.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`ECB`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    /// - Use double [`DES`] keys to perform corresponding 2-key 3DES encryption.
    ///
    /// [`128`]: enum.KeyLength.html#variant.Bits
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    /// [`DES`]: enum.KeyType.html#variant.Des
    UnsafeTrippleDes2Tdea,

    /// 3DES 3-key encryption
    ///
    /// - Supported key lengths: [`192`] bits.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`CFB1`],
    ///   * [`CFB8`],
    ///   * [`ECB`],
    ///   * [`Wrap`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    /// - Use triple [`DES`] keys to perform corresponding 3-key 3DES encryption.
    ///
    /// [`192`]: enum.KeyLength.html#variant.Bits
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`CFB1`]: enum.BlockCipherMode.html#variant.Cfb1
    /// [`CFB8`]: enum.BlockCipherMode.html#variant.Cfb8
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`Wrap`]: enum.BlockCipherMode.html#variant.Wrap
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    /// [`DES`]: enum.KeyType.html#variant.Des
    TrippleDes3Tdea,

    /// RC2 encryption (unsafe)
    ///
    /// - This is a variable key length cipher.
    /// - Supported key lengths: 8-1024 bits in steps of 8 bits.
    /// - Effective key bits property by default equals to 128 bits.
    ///   Possible values are 1-1024 in steps of 1 bit.
    ///   Effective key bits can be set using [`CtxRc2::set_property_rc2_effective_key_bits()`].  
    ///   It can be set after [`EncryptContext::initialize()`] / [`DecryptContext::initialize()`],
    ///   and before [`EncryptContext::update()`] / [`DecryptContext::update()`] in
    ///   encryption / decryption operation.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`ECB`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    ///
    /// [`CtxRc2::set_property_rc2_effective_key_bits()`]: trait.ContextWithRc2Supported.html#method.set_property_rc2_effective_key_bits
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    UnsafeRc2,

    /// RC4 encryption (unsafe)
    ///
    /// - This is a variable key length cipher.
    /// - Supported key lengths: 40–2048 bits in steps of 8 bits.
    /// - Initialization Vector is not used.
    /// - This cipher doesn't support block cipher modes, use [`BlockCipherMode::None`] instead.
    ///
    /// [`BlockCipherMode::None`]: enum.BlockCipherMode.html#variant.None
    UnsafeRc4,

    /// CAST5 encryption
    ///
    /// - This is a variable key length cipher.
    /// - Supported key lengths: 40-128 bits in steps of 8 bits.
    /// - Supported block cipher modes:
    ///   * [`CBC`],
    ///   * [`OFB`],
    ///   * [`CFB`],
    ///   * [`ECB`].
    /// - See [`BlockCipherMode`] for details on additional properties (mandatory).
    ///
    /// [`CBC`]: enum.BlockCipherMode.html#variant.Cbc
    /// [`OFB`]: enum.BlockCipherMode.html#variant.Ofb
    /// [`CFB`]: enum.BlockCipherMode.html#variant.Cfb
    /// [`ECB`]: enum.BlockCipherMode.html#variant.Ecb
    /// [`BlockCipherMode`]: enum.BlockCipherMode.html
    Cast5,
}

/// Enumeration of YACA chaining modes for block ciphers
#[derive(Debug, PartialEq)]
pub enum BlockCipherMode {
    /// Used when algorithm doesn't support block ciphers modes.
    ///
    /// - Initialization Vector is not used.
    None,

    /// ECB block cipher mode.
    ///
    /// - Initialization Vector is not used.
    /// - By default the input data is padded using standard block
    ///   padding [`PKCS7`].
    /// - Padding can be disabled using
    ///   [`CtxPad::set_property_padding()`] and [`Padding::None`].
    ///   The total length of data passed until `*::finalize()` must
    ///   be a multiple of block size in such case.
    /// - In case of `Encrypt`/`Seal` [`Padding`] can be set at
    ///   the latest before the `*::finalize()` call. In case of
    ///   `Decrypt`/`Open` it can be set at the latest before the
    ///   `*::update()` call.
    ///
    /// [`PKCS7`]: enum.Padding.html#variant.Pkcs7
    /// [`CtxPad::set_property_padding()`]: trait.ContextWithPadding.html#method.set_property_padding
    /// [`Padding::None`]: enum.Padding.html#variant.None
    /// [`Padding`]: enum.Padding.html
    Ecb,

    /// CTR block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`],
    ///   64-bit for other algorithms is mandatory.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    Ctr,

    /// CBC block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`].
    /// - 64-bit for other algorithms is mandatory.
    /// - By default the input data is padded using standard block
    ///   padding [`PKCS7`].
    /// - Padding can be disabled using
    ///   [`CtxPad::set_property_padding`] and [`Padding::None`].
    ///   The total length of data passed until `*::finalize()` must
    ///   be a multiple of block size in such case.
    /// - In case of `Encrypt`/`Seal` [`Padding`] can be set at
    ///   the latest before the `*::finalize()` call. In case of
    ///   `Decrypt`/`Open` it can be set at the latest before the
    ///   `*::update()` call.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    /// [`PKCS7`]: enum.Padding.html#variant.Pkcs7
    /// [`CtxPad::set_property_padding`]: trait.ContextWithPadding.html#method.set_property_padding
    /// [`Padding::None`]: enum.Padding.html#variant.None
    /// [`Padding`]: enum.Padding.html
    Cbc,

    /// GCM block cipher mode
    ///
    /// - This is a variable [`Initialization Vector`] length mode (recommended 96-bits).
    /// - Supported properties:
    ///   * GCM tag length (optional)  
    ///     [`CtxXcmEnc::set_property_gcm_tag_len()`]  
    ///     Supported tag lengths: 4, 8, 12, 13, 14, 15, 16 (16 bytes tag by default).  
    ///     Set after [`EncryptContext::finalize()`] / [`SealContext::finalize()`] and before
    ///     [`CtxXcmEnc::get_property_gcm_tag()`] in `Encryption`/`Seal` operation.
    ///     In `Decryption`/`Open` operation tag length is not set.
    ///   * GCM tag  
    ///     [`CtxXcmEnc::get_property_gcm_tag()`]  
    ///     [`CtxXcmDec::set_property_gcm_tag()`]  
    ///     Get after [`EncryptContext::finalize()`] / [`SealContext::finalize()`] in `Encryption`/`Seal` operation.  
    ///     Set after [`DecryptContext::update()`] / [`OpenContext::update()`] and before
    ///     [`DecryptContext::finalize()`] / [`OpenContext::finalize()`] in `Decryption`/`Open` operation.
    ///   * AAD - additional authentication data (optional)  
    ///     [`CtxXcmEnc::set_property_gcm_aad()`]  
    ///     [`CtxXcmDec::set_property_gcm_aad()`]  
    ///     AAD length can have any positive value.  
    ///     Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///     [`EncryptContext::update()`] / [`SealContext::update()`] in `Encryption`/`Seal` operation.  
    ///     Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///     [`DecryptContext::update()`] / [`OpenContext::update()`] in `Decryption`/`Open` operation.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`CtxXcmEnc::set_property_gcm_tag_len()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_gcm_tag_len
    /// [`EncryptContext::finalize()`]: struct.EncryptContext.html#method.finalize
    /// [`SealContext::finalize()`]: struct.SealContext.html#method.finalize
    /// [`CtxXcmEnc::get_property_gcm_tag()`]: trait.ContextWithXcmEncryptProperties.html#method.get_property_gcm_tag
    /// [`CtxXcmDec::set_property_gcm_tag()`]: trait.ContextWithXcmDecryptProperties.html#method.set_property_gcm_tag
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`DecryptContext::finalize()`]: struct.DecryptContext.html#method.finalize
    /// [`OpenContext::finalize()`]: struct.OpenContext.html#method.finalize
    /// [`CtxXcmEnc::set_property_gcm_aad()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_gcm_aad
    /// [`CtxXcmDec::set_property_gcm_aad()`]: trait.ContextWithXcmDecryptProperties.html#method.set_property_gcm_aad
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`SealContext::update()`]: struct.SealContext.html#method.update
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    Gcm,

    /// Default CFB block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`],
    ///   64-bit for other algorithms is mandatory.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    Cfb,

    /// 1 bit CFB block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`],
    ///   64-bit for other algorithms is mandatory.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    Cfb1,

    /// 8 bits CFB block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`],
    ///   64-bit for other algorithms is mandatory.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    Cfb8,

    /// OFB block cipher mode
    ///
    /// - 128-bit [`Initialization Vector`] for [`AES`],
    ///   64-bit for other algorithms is mandatory.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    Ofb,

    /// CBC-MAC Mode (AES)
    ///
    /// - This is a variable [`Initialization Vector`] length mode.
    /// - Supported [`Initialization Vector`] lengths: 56-104 bits in steps of 8 bits
    ///   (recommended 56-bits).
    /// - Supported properties:
    ///   * CCM tag length (optional)  
    ///     [`CtxXcmEnc::set_property_ccm_tag_len()`]  
    ///     Supported tag lengths: 4-16 bytes in steps of 2 bytes (12 bytes tag by default).  
    ///     Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///     [`EncryptContext::update()`] / [`SealContext::update()`] in `Encryption`/`Seal` operation.  
    ///     In `Decryption`/`Open` operation tag length is not set.  
    ///   * CCM tag  
    ///     [`CtxXcmEnc::get_property_ccm_tag()`]  
    ///     [`CtxXcmDec::set_property_ccm_tag()`]  
    ///     Get after [`EncryptContext::finalize()`] / [`SealContext::finalize()`] in `Encryption`/`Seal` operation.  
    ///     Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///     [`DecryptContext::update()`] / [`OpenContext::update()`] in decryption / open operation.  
    ///   * AAD - additional authentication data (optional)  
    ///     [`CtxXcmEnc::set_property_ccm_aad()`]  
    ///     [`CtxXcmDec::set_property_ccm_aad()`]  
    ///     AAD length can have any positive value.
    ///
    ///     The total plaintext length must be passed to [`CtxXcmEnc::set_property_ccm_aad()`] if AAD is used.  
    ///     Set after [`EncryptContext::initialize()`] / [`SealContext::initialize()`] and before
    ///     [`EncryptContext::update()`] / [`SealContext::update()`] in `Encryption`/`Seal` operation.
    ///
    ///     The total ciphertext length must be passed to [`CtxXcmDec::set_property_ccm_aad()`] if AAD is used.  
    ///     Set after [`DecryptContext::initialize()`] / [`OpenContext::initialize()`] and before
    ///     [`DecryptContext::update()`] / [`OpenContext::update()`] in `Decryption`/`Open` operation.
    ///
    /// - You can only call [`EncryptContext::update()`] / [`SealContext::update()`] once for the plaintext.  
    ///   You can only call [`DecryptContext::update()`] / [`OpenContext::update()`] once for the ciphertext.
    ///
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`CtxXcmEnc::set_property_ccm_tag_len()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_ccm_tag_len
    /// [`EncryptContext::initialize()`]: struct.EncryptContext.html#method.initialize
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`SealContext::update()`]: struct.SealContext.html#method.update
    /// [`CtxXcmEnc::get_property_ccm_tag()`]: trait.ContextWithXcmEncryptProperties.html#method.get_property_ccm_tag
    /// [`CtxXcmDec::set_property_ccm_tag()`]: trait.ContextWithXcmDecryptProperties.html#method.set_property_ccm_tag
    /// [`EncryptContext::finalize()`]: struct.EncryptContext.html#method.finalize
    /// [`SealContext::finalize()`]: struct.SealContext.html#method.finalize
    /// [`DecryptContext::initialize()`]: struct.DecryptContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`OpenContext::update()`]: struct.OpenContext.html#method.update
    /// [`CtxXcmEnc::set_property_ccm_aad()`]: trait.ContextWithXcmEncryptProperties.html#method.set_property_ccm_aad
    /// [`CtxXcmDec::set_property_ccm_aad()`]: trait.ContextWithXcmDecryptProperties.html#method.set_property_ccm_aad
    Ccm,

    /// Used with [`AES`] or [`3DES_3TDEA`] to perform a key wrapping
    /// (key material symmetric encryption)
    ///
    /// - Only a single [`EncryptContext::update()`] / [`DecryptContext::update()`] is allowed.
    /// - Usage in [`SealContext::initialize()`] / [`OpenContext::initialize()`] is forbidden.
    /// - Key used to do the wrapping with [`EncryptAlgorithm::Aes`] can be a [`128`], [`192`] or a [`256`] bit key.  
    ///   [`64`] bit [`Initialization Vector`] is used.  
    ///   Wrapped key can be a [`128`], [`192`], or a [`256`] bit key.  
    ///   [`EncryptAlgorithm::Aes`] allows wrapping multiple keys together.
    /// - Key used to do the wrapping with [`EncryptAlgorithm::UnsafeTrippleDes2Tdea`] can be a [`192`] bit [`DES`] key only.
    ///   Initialization Vector is not used.  
    ///   Wrapped key can be a [`128`] bit [`DES`] key (two-key), or a [`192`] bit [`DES`] key (three-key).  
    ///   [`EncryptAlgorithm::UnsafeTrippleDes2Tdea`] allows wrapping only one key.
    ///
    /// [`AES`]: enum.EncryptAlgorithm.html#variant.Aes
    /// [`Initialization Vector`]: enum.KeyType.html#variant.Iv
    /// [`3DES_3TDEA`]: enum.EncryptAlgorithm.html#variant.UnsafeTrippleDes2Tdea
    /// [`EncryptContext::update()`]: struct.EncryptContext.html#method.update
    /// [`DecryptContext::update()`]: struct.DecryptContext.html#method.update
    /// [`SealContext::initialize()`]: struct.SealContext.html#method.initialize
    /// [`OpenContext::initialize()`]: struct.OpenContext.html#method.initialize
    /// [`EncryptAlgorithm::Aes`]: enum.EncryptAlgorithm.html#variant.Aes
    /// [`EncryptAlgorithm::UnsafeTrippleDes2Tdea`]: enum.EncryptAlgorithm.html#variant.UnsafeTrippleDes2Tdea
    /// [`64`]: enum.KeyLength.html#variant.Bits
    /// [`128`]: enum.KeyLength.html#variant.Bits
    /// [`192`]: enum.KeyLength.html#variant.Bits
    /// [`256`]: enum.KeyLength.html#variant.Bits
    /// [`DES`]: enum.KeyType.html#variant.Des
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

/// Enumeration of YACA paddings
#[derive(Debug, PartialEq)]
pub enum Padding {
    /// No padding at all. This method assumes that the input data
    /// already has a proper length for a given cryptographic
    /// operation (e.g. it has been padded by the client). Suitable
    /// for symmetric `Encrypt`/`Decrypt` operations as well as low-level
    /// `RSA` operations.
    None,

    /// X9.31 padding. Suitable for `RSA` `Sign`/`Verify` operation. Not
    /// supported in low-level `RSA` operations.
    X931,

    /// PKCS #1 v1.5 padding. Suitable for `RSA` `Sign`/`Verify` and
    /// low-level `RSA` operations. For low-level operations the input
    /// must be at least 11 bytes shorter than the key length.
    Pkcs1,

    /// PKCS #1 PSS padding. Suitable for `RSA` `Sign`/`Verify`
    /// operations. Not supported in low-level `RSA` operations.
    Pkcs1Pss,

    /// EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an
    /// empty encoding parameter. Suitable for low-level `RSA`
    /// public_encrypt/private_decrypt operations. For low-level
    /// operations the input must be at least 42 bytes shorter than
    /// the key length.
    Pkcs1Oaep,

    /// PKCS #1 v1.5 padding with an SSL-specific modification that
    /// denotes that the party is SSL3 capable. It is used for
    /// rollback attack detection in SSLv3. If during decryption it
    /// turns out that both parties are using `Pkcs1SslV23` (both are
    /// communicating using SSL2 and both are SSL3 capable) it is
    /// treated as a rollback attack and an error is
    /// returned. Suitable for low-level `RSA`
    /// `public_encrypt`/`private_decrypt` operations. For low-level
    /// operations the input must be at least 11 bytes shorter than
    /// the key length.
    Pkcs1SslV23,

    /// PKCS #7 padding. Suitable for symmetric `Encrypt`/`Decrypt` operation.
    Pkcs7,
}

/// Enumeration of YACA key derivation functions
#[derive(Debug, PartialEq)]
pub enum Kdf {
    /// ANSI X9.42 key derivation function, (shared secret derived
    /// using Diffie-Hellman key exchange protocol).
    X942,

    /// ANSI X9.62 key derivation function, (shared secret derived
    /// using EC Diffie-Hellman key exchange protocol).
    X962,
}

// Local Variables:
// delete-trailing-whitespace-on-save: nil
// End:
