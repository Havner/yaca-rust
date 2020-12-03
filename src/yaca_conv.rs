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

use libc::{c_int, size_t, EINVAL, ENOMEM};

use crate::*;


const BASE_ERROR_YACA:              c_int = -0x01E30000;
const YACA_ERROR_NONE:              c_int = 0;
const YACA_ERROR_INVALID_PARAMETER: c_int = -EINVAL;
const YACA_ERROR_OUT_OF_MEMORY:     c_int = -ENOMEM;
const YACA_ERROR_INTERNAL:          c_int = BASE_ERROR_YACA | 0x01;
const YACA_ERROR_DATA_MISMATCH:     c_int = BASE_ERROR_YACA | 0x02;
const YACA_ERROR_INVALID_PASSWORD:  c_int = BASE_ERROR_YACA | 0x03;

pub(crate) fn res_c_to_rs(r: c_int) -> Result<()>
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

pub(crate) fn res_c_to_rs_bool(r: c_int) -> Result<bool>
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
        KeyType::RsaPublic => YACA_KEY_TYPE_RSA_PUB,
        KeyType::RsaPrivate => YACA_KEY_TYPE_RSA_PRIV,
        KeyType::DsaPublic => YACA_KEY_TYPE_DSA_PUB,
        KeyType::DsaPrivate => YACA_KEY_TYPE_DSA_PRIV,
        KeyType::DhPublic => YACA_KEY_TYPE_DH_PUB,
        KeyType::DhPrivate => YACA_KEY_TYPE_DH_PRIV,
        KeyType::EcPublic => YACA_KEY_TYPE_EC_PUB,
        KeyType::EcPrivate => YACA_KEY_TYPE_EC_PRIV,
        KeyType::DsaParams => YACA_KEY_TYPE_DSA_PARAMS,
        KeyType::DhParams => YACA_KEY_TYPE_DH_PARAMS,
        KeyType::EcParams => YACA_KEY_TYPE_EC_PARAMS,
    }
}

pub(crate) fn key_type_c_to_rs(kt: c_int) -> KeyType
{
    match kt {
        YACA_KEY_TYPE_SYMMETRIC => KeyType::Symmetric,
        YACA_KEY_TYPE_DES => KeyType::Des,
        YACA_KEY_TYPE_IV => KeyType::Iv,
        YACA_KEY_TYPE_RSA_PRIV => KeyType::RsaPrivate,
        YACA_KEY_TYPE_RSA_PUB => KeyType::RsaPublic,
        YACA_KEY_TYPE_DSA_PRIV => KeyType::DsaPrivate,
        YACA_KEY_TYPE_DSA_PUB => KeyType::DsaPublic,
        YACA_KEY_TYPE_DSA_PARAMS => KeyType::DsaParams,
        YACA_KEY_TYPE_EC_PRIV => KeyType::EcPrivate,
        YACA_KEY_TYPE_EC_PUB => KeyType::EcPublic,
        YACA_KEY_TYPE_EC_PARAMS => KeyType::EcParams,
        YACA_KEY_TYPE_DH_PRIV => KeyType::DhPrivate,
        YACA_KEY_TYPE_DH_PUB => KeyType::DhPublic,
        YACA_KEY_TYPE_DH_PARAMS => KeyType::DhParams,
        x => {
            debug_assert!(false, "Wrong key_type passed from C: {}", x);
            KeyType::Symmetric
        },
    }
}

const YACA_KEY_LENGTH_EC_PRIME192V1: c_int = 0x300000C0;
const YACA_KEY_LENGTH_EC_PRIME192V2: c_int = 0x300100C0;
const YACA_KEY_LENGTH_EC_PRIME192V3: c_int = 0x300200C0;
const YACA_KEY_LENGTH_EC_PRIME239V1: c_int = 0x300000EF;
const YACA_KEY_LENGTH_EC_PRIME239V2: c_int = 0x300100EF;
const YACA_KEY_LENGTH_EC_PRIME239V3: c_int = 0x300200EF;
const YACA_KEY_LENGTH_EC_PRIME256V1: c_int = 0x30000100;

const YACA_KEY_LENGTH_EC_C2PNB163V1: c_int = 0x340000A3;
const YACA_KEY_LENGTH_EC_C2PNB163V2: c_int = 0x340100A3;
const YACA_KEY_LENGTH_EC_C2PNB163V3: c_int = 0x340200A3;
const YACA_KEY_LENGTH_EC_C2PNB176V1: c_int = 0x340000B0;
const YACA_KEY_LENGTH_EC_C2TNB191V1: c_int = 0x350000BF;
const YACA_KEY_LENGTH_EC_C2TNB191V2: c_int = 0x350100BF;
const YACA_KEY_LENGTH_EC_C2TNB191V3: c_int = 0x350200BF;
const YACA_KEY_LENGTH_EC_C2PNB208W1: c_int = 0x344000D0;
const YACA_KEY_LENGTH_EC_C2TNB239V1: c_int = 0x350000EF;
const YACA_KEY_LENGTH_EC_C2TNB239V2: c_int = 0x350100EF;
const YACA_KEY_LENGTH_EC_C2TNB239V3: c_int = 0x350200EF;
const YACA_KEY_LENGTH_EC_C2PNB272W1: c_int = 0x34400110;
const YACA_KEY_LENGTH_EC_C2PNB304W1: c_int = 0x34400130;
const YACA_KEY_LENGTH_EC_C2TNB359V1: c_int = 0x35000167;
const YACA_KEY_LENGTH_EC_C2PNB368W1: c_int = 0x34400170;
const YACA_KEY_LENGTH_EC_C2TNB431R1: c_int = 0x351001AF;

const YACA_KEY_LENGTH_EC_SECP112R1: c_int = 0x31100070;
const YACA_KEY_LENGTH_EC_SECP112R2: c_int = 0x31110070;
const YACA_KEY_LENGTH_EC_SECP128R1: c_int = 0x31100080;
const YACA_KEY_LENGTH_EC_SECP128R2: c_int = 0x31110080;
const YACA_KEY_LENGTH_EC_SECP160K1: c_int = 0x312000A0;
const YACA_KEY_LENGTH_EC_SECP160R1: c_int = 0x311000A0;
const YACA_KEY_LENGTH_EC_SECP160R2: c_int = 0x311100A0;
const YACA_KEY_LENGTH_EC_SECP192K1: c_int = 0x312000C0;
const YACA_KEY_LENGTH_EC_SECP224K1: c_int = 0x312000E0;
const YACA_KEY_LENGTH_EC_SECP224R1: c_int = 0x311000E0;
const YACA_KEY_LENGTH_EC_SECP256K1: c_int = 0x31200100;
const YACA_KEY_LENGTH_EC_SECP384R1: c_int = 0x31100180;
const YACA_KEY_LENGTH_EC_SECP521R1: c_int = 0x31100209;

const YACA_KEY_LENGTH_EC_SECT113R1: c_int = 0x32100071;
const YACA_KEY_LENGTH_EC_SECT113R2: c_int = 0x32110071;
const YACA_KEY_LENGTH_EC_SECT131R1: c_int = 0x32100083;
const YACA_KEY_LENGTH_EC_SECT131R2: c_int = 0x32110083;
const YACA_KEY_LENGTH_EC_SECT163K1: c_int = 0x322000A3;
const YACA_KEY_LENGTH_EC_SECT163R1: c_int = 0x321000A3;
const YACA_KEY_LENGTH_EC_SECT163R2: c_int = 0x321100A3;
const YACA_KEY_LENGTH_EC_SECT193R1: c_int = 0x321000C1;
const YACA_KEY_LENGTH_EC_SECT193R2: c_int = 0x321100C1;
const YACA_KEY_LENGTH_EC_SECT233K1: c_int = 0x322000E9;
const YACA_KEY_LENGTH_EC_SECT233R1: c_int = 0x321000E9;
const YACA_KEY_LENGTH_EC_SECT239K1: c_int = 0x322000EF;
const YACA_KEY_LENGTH_EC_SECT283K1: c_int = 0x3220011B;
const YACA_KEY_LENGTH_EC_SECT283R1: c_int = 0x3210011B;
const YACA_KEY_LENGTH_EC_SECT409K1: c_int = 0x32200199;
const YACA_KEY_LENGTH_EC_SECT409R1: c_int = 0x32100199;
const YACA_KEY_LENGTH_EC_SECT571K1: c_int = 0x3220023B;
const YACA_KEY_LENGTH_EC_SECT571R1: c_int = 0x3210023B;

const YACA_KEY_LENGTH_EC_BRAINPOOLP160R1: c_int = 0x331000A0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP160T1: c_int = 0x333000A0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP192R1: c_int = 0x331000C0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP192T1: c_int = 0x333000C0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP224R1: c_int = 0x331000E0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP224T1: c_int = 0x333000E0;
const YACA_KEY_LENGTH_EC_BRAINPOOLP256R1: c_int = 0x33100100;
const YACA_KEY_LENGTH_EC_BRAINPOOLP256T1: c_int = 0x33300100;
const YACA_KEY_LENGTH_EC_BRAINPOOLP320R1: c_int = 0x33100140;
const YACA_KEY_LENGTH_EC_BRAINPOOLP320T1: c_int = 0x33300140;
const YACA_KEY_LENGTH_EC_BRAINPOOLP384R1: c_int = 0x33100180;
const YACA_KEY_LENGTH_EC_BRAINPOOLP384T1: c_int = 0x33300180;
const YACA_KEY_LENGTH_EC_BRAINPOOLP512R1: c_int = 0x33100200;
const YACA_KEY_LENGTH_EC_BRAINPOOLP512T1: c_int = 0x33300200;

const YACA_KEY_LENGTH_DH_RFC_1024_160: c_int = 0x20000400;
const YACA_KEY_LENGTH_DH_RFC_2048_224: c_int = 0x21000800;
const YACA_KEY_LENGTH_DH_RFC_2048_256: c_int = 0x22000800;

const YACA_KEY_LENGTH_DH_GENERATOR_2: c_int = 0x10000000;
const YACA_KEY_LENGTH_DH_GENERATOR_5: c_int = 0x11000000;

pub(crate) fn key_length_rs_to_c(kl: &KeyLength) -> size_t
{
    match kl {
        KeyLength::Bits(bl) => *bl as size_t,

        KeyLength::Ec(Prime192V1) => YACA_KEY_LENGTH_EC_PRIME192V1 as size_t,
        KeyLength::Ec(Prime192V2) => YACA_KEY_LENGTH_EC_PRIME192V2 as size_t,
        KeyLength::Ec(Prime192V3) => YACA_KEY_LENGTH_EC_PRIME192V3 as size_t,
        KeyLength::Ec(Prime239V1) => YACA_KEY_LENGTH_EC_PRIME239V1 as size_t,
        KeyLength::Ec(Prime239V2) => YACA_KEY_LENGTH_EC_PRIME239V2 as size_t,
        KeyLength::Ec(Prime239V3) => YACA_KEY_LENGTH_EC_PRIME239V3 as size_t,
        KeyLength::Ec(Prime256V1) => YACA_KEY_LENGTH_EC_PRIME256V1 as size_t,

        KeyLength::Ec(C2pnb163V1) => YACA_KEY_LENGTH_EC_C2PNB163V1 as size_t,
        KeyLength::Ec(C2pnb163V2) => YACA_KEY_LENGTH_EC_C2PNB163V2 as size_t,
        KeyLength::Ec(C2pnb163V3) => YACA_KEY_LENGTH_EC_C2PNB163V3 as size_t,
        KeyLength::Ec(C2pnb176V1) => YACA_KEY_LENGTH_EC_C2PNB176V1 as size_t,
        KeyLength::Ec(C2tnb191V1) => YACA_KEY_LENGTH_EC_C2TNB191V1 as size_t,
        KeyLength::Ec(C2tnb191V2) => YACA_KEY_LENGTH_EC_C2TNB191V2 as size_t,
        KeyLength::Ec(C2tnb191V3) => YACA_KEY_LENGTH_EC_C2TNB191V3 as size_t,
        KeyLength::Ec(C2pnb208W1) => YACA_KEY_LENGTH_EC_C2PNB208W1 as size_t,
        KeyLength::Ec(C2tnb239V1) => YACA_KEY_LENGTH_EC_C2TNB239V1 as size_t,
        KeyLength::Ec(C2tnb239V2) => YACA_KEY_LENGTH_EC_C2TNB239V2 as size_t,
        KeyLength::Ec(C2tnb239V3) => YACA_KEY_LENGTH_EC_C2TNB239V3 as size_t,
        KeyLength::Ec(C2pnb272W1) => YACA_KEY_LENGTH_EC_C2PNB272W1 as size_t,
        KeyLength::Ec(C2pnb304W1) => YACA_KEY_LENGTH_EC_C2PNB304W1 as size_t,
        KeyLength::Ec(C2tnb359V1) => YACA_KEY_LENGTH_EC_C2TNB359V1 as size_t,
        KeyLength::Ec(C2pnb368W1) => YACA_KEY_LENGTH_EC_C2PNB368W1 as size_t,
        KeyLength::Ec(C2tnb431R1) => YACA_KEY_LENGTH_EC_C2TNB431R1 as size_t,

        KeyLength::Ec(Secp112R1) => YACA_KEY_LENGTH_EC_SECP112R1 as size_t,
        KeyLength::Ec(Secp112R2) => YACA_KEY_LENGTH_EC_SECP112R2 as size_t,
        KeyLength::Ec(Secp128R1) => YACA_KEY_LENGTH_EC_SECP128R1 as size_t,
        KeyLength::Ec(Secp128R2) => YACA_KEY_LENGTH_EC_SECP128R2 as size_t,
        KeyLength::Ec(Secp160K1) => YACA_KEY_LENGTH_EC_SECP160K1 as size_t,
        KeyLength::Ec(Secp160R1) => YACA_KEY_LENGTH_EC_SECP160R1 as size_t,
        KeyLength::Ec(Secp160R2) => YACA_KEY_LENGTH_EC_SECP160R2 as size_t,
        KeyLength::Ec(Secp192K1) => YACA_KEY_LENGTH_EC_SECP192K1 as size_t,
        KeyLength::Ec(Secp224K1) => YACA_KEY_LENGTH_EC_SECP224K1 as size_t,
        KeyLength::Ec(Secp224R1) => YACA_KEY_LENGTH_EC_SECP224R1 as size_t,
        KeyLength::Ec(Secp256K1) => YACA_KEY_LENGTH_EC_SECP256K1 as size_t,
        KeyLength::Ec(Secp384R1) => YACA_KEY_LENGTH_EC_SECP384R1 as size_t,
        KeyLength::Ec(Secp521R1) => YACA_KEY_LENGTH_EC_SECP521R1 as size_t,

        KeyLength::Ec(Sect113R1) => YACA_KEY_LENGTH_EC_SECT113R1 as size_t,
        KeyLength::Ec(Sect113R2) => YACA_KEY_LENGTH_EC_SECT113R2 as size_t,
        KeyLength::Ec(Sect131R1) => YACA_KEY_LENGTH_EC_SECT131R1 as size_t,
        KeyLength::Ec(Sect131R2) => YACA_KEY_LENGTH_EC_SECT131R2 as size_t,
        KeyLength::Ec(Sect163K1) => YACA_KEY_LENGTH_EC_SECT163K1 as size_t,
        KeyLength::Ec(Sect163R1) => YACA_KEY_LENGTH_EC_SECT163R1 as size_t,
        KeyLength::Ec(Sect163R2) => YACA_KEY_LENGTH_EC_SECT163R2 as size_t,
        KeyLength::Ec(Sect193R1) => YACA_KEY_LENGTH_EC_SECT193R1 as size_t,
        KeyLength::Ec(Sect193R2) => YACA_KEY_LENGTH_EC_SECT193R2 as size_t,
        KeyLength::Ec(Sect233K1) => YACA_KEY_LENGTH_EC_SECT233K1 as size_t,
        KeyLength::Ec(Sect233R1) => YACA_KEY_LENGTH_EC_SECT233R1 as size_t,
        KeyLength::Ec(Sect239K1) => YACA_KEY_LENGTH_EC_SECT239K1 as size_t,
        KeyLength::Ec(Sect283K1) => YACA_KEY_LENGTH_EC_SECT283K1 as size_t,
        KeyLength::Ec(Sect283R1) => YACA_KEY_LENGTH_EC_SECT283R1 as size_t,
        KeyLength::Ec(Sect409K1) => YACA_KEY_LENGTH_EC_SECT409K1 as size_t,
        KeyLength::Ec(Sect409R1) => YACA_KEY_LENGTH_EC_SECT409R1 as size_t,
        KeyLength::Ec(Sect571K1) => YACA_KEY_LENGTH_EC_SECT571K1 as size_t,
        KeyLength::Ec(Sect571R1) => YACA_KEY_LENGTH_EC_SECT571R1 as size_t,

        KeyLength::Ec(BrainpoolP160R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP160R1 as size_t,
        KeyLength::Ec(BrainpoolP160T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP160T1 as size_t,
        KeyLength::Ec(BrainpoolP192R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP192R1 as size_t,
        KeyLength::Ec(BrainpoolP192T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP192T1 as size_t,
        KeyLength::Ec(BrainpoolP224R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP224R1 as size_t,
        KeyLength::Ec(BrainpoolP224T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP224T1 as size_t,
        KeyLength::Ec(BrainpoolP256R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP256R1 as size_t,
        KeyLength::Ec(BrainpoolP256T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP256T1 as size_t,
        KeyLength::Ec(BrainpoolP320R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP320R1 as size_t,
        KeyLength::Ec(BrainpoolP320T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP320T1 as size_t,
        KeyLength::Ec(BrainpoolP384R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP384R1 as size_t,
        KeyLength::Ec(BrainpoolP384T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP384T1 as size_t,
        KeyLength::Ec(BrainpoolP512R1) => YACA_KEY_LENGTH_EC_BRAINPOOLP512R1 as size_t,
        KeyLength::Ec(BrainpoolP512T1) => YACA_KEY_LENGTH_EC_BRAINPOOLP512T1 as size_t,

        KeyLength::Dh(Rfc1024_160) => YACA_KEY_LENGTH_DH_RFC_1024_160 as size_t,
        KeyLength::Dh(Rfc2048_224) => YACA_KEY_LENGTH_DH_RFC_2048_224 as size_t,
        KeyLength::Dh(Rfc2048_256) => YACA_KEY_LENGTH_DH_RFC_2048_256 as size_t,
        KeyLength::Dh(Generator2Bits(bl)) =>
            (YACA_KEY_LENGTH_DH_GENERATOR_2 as size_t | *bl as size_t),
        KeyLength::Dh(Generator5Bits(bl)) =>
            (YACA_KEY_LENGTH_DH_GENERATOR_5 as size_t | *bl as size_t),
    }
}

pub(crate) fn key_length_c_to_rs(kl: size_t) -> KeyLength
{
    const MAX_BITS: c_int = std::u16::MAX as c_int;
    match kl as c_int {
        YACA_KEY_LENGTH_EC_PRIME192V1 => KeyLength::Ec(Prime192V1),
        YACA_KEY_LENGTH_EC_PRIME192V2 => KeyLength::Ec(Prime192V2),
        YACA_KEY_LENGTH_EC_PRIME192V3 => KeyLength::Ec(Prime192V3),
        YACA_KEY_LENGTH_EC_PRIME239V1 => KeyLength::Ec(Prime239V1),
        YACA_KEY_LENGTH_EC_PRIME239V2 => KeyLength::Ec(Prime239V2),
        YACA_KEY_LENGTH_EC_PRIME239V3 => KeyLength::Ec(Prime239V3),
        YACA_KEY_LENGTH_EC_PRIME256V1 => KeyLength::Ec(Prime256V1),

        YACA_KEY_LENGTH_EC_C2PNB163V1 => KeyLength::Ec(C2pnb163V1),
        YACA_KEY_LENGTH_EC_C2PNB163V2 => KeyLength::Ec(C2pnb163V2),
        YACA_KEY_LENGTH_EC_C2PNB163V3 => KeyLength::Ec(C2pnb163V3),
        YACA_KEY_LENGTH_EC_C2PNB176V1 => KeyLength::Ec(C2pnb176V1),
        YACA_KEY_LENGTH_EC_C2TNB191V1 => KeyLength::Ec(C2tnb191V1),
        YACA_KEY_LENGTH_EC_C2TNB191V2 => KeyLength::Ec(C2tnb191V2),
        YACA_KEY_LENGTH_EC_C2TNB191V3 => KeyLength::Ec(C2tnb191V3),
        YACA_KEY_LENGTH_EC_C2PNB208W1 => KeyLength::Ec(C2pnb208W1),
        YACA_KEY_LENGTH_EC_C2TNB239V1 => KeyLength::Ec(C2tnb239V1),
        YACA_KEY_LENGTH_EC_C2TNB239V2 => KeyLength::Ec(C2tnb239V2),
        YACA_KEY_LENGTH_EC_C2TNB239V3 => KeyLength::Ec(C2tnb239V3),
        YACA_KEY_LENGTH_EC_C2PNB272W1 => KeyLength::Ec(C2pnb272W1),
        YACA_KEY_LENGTH_EC_C2PNB304W1 => KeyLength::Ec(C2pnb304W1),
        YACA_KEY_LENGTH_EC_C2TNB359V1 => KeyLength::Ec(C2tnb359V1),
        YACA_KEY_LENGTH_EC_C2PNB368W1 => KeyLength::Ec(C2pnb368W1),
        YACA_KEY_LENGTH_EC_C2TNB431R1 => KeyLength::Ec(C2tnb431R1),

        YACA_KEY_LENGTH_EC_SECP112R1 => KeyLength::Ec(Secp112R1),
        YACA_KEY_LENGTH_EC_SECP112R2 => KeyLength::Ec(Secp112R2),
        YACA_KEY_LENGTH_EC_SECP128R1 => KeyLength::Ec(Secp128R1),
        YACA_KEY_LENGTH_EC_SECP128R2 => KeyLength::Ec(Secp128R2),
        YACA_KEY_LENGTH_EC_SECP160K1 => KeyLength::Ec(Secp160K1),
        YACA_KEY_LENGTH_EC_SECP160R1 => KeyLength::Ec(Secp160R1),
        YACA_KEY_LENGTH_EC_SECP160R2 => KeyLength::Ec(Secp160R2),
        YACA_KEY_LENGTH_EC_SECP192K1 => KeyLength::Ec(Secp192K1),
        YACA_KEY_LENGTH_EC_SECP224K1 => KeyLength::Ec(Secp224K1),
        YACA_KEY_LENGTH_EC_SECP224R1 => KeyLength::Ec(Secp224R1),
        YACA_KEY_LENGTH_EC_SECP256K1 => KeyLength::Ec(Secp256K1),
        YACA_KEY_LENGTH_EC_SECP384R1 => KeyLength::Ec(Secp384R1),
        YACA_KEY_LENGTH_EC_SECP521R1 => KeyLength::Ec(Secp521R1),

        YACA_KEY_LENGTH_EC_SECT113R1 => KeyLength::Ec(Sect113R1),
        YACA_KEY_LENGTH_EC_SECT113R2 => KeyLength::Ec(Sect113R2),
        YACA_KEY_LENGTH_EC_SECT131R1 => KeyLength::Ec(Sect131R1),
        YACA_KEY_LENGTH_EC_SECT131R2 => KeyLength::Ec(Sect131R2),
        YACA_KEY_LENGTH_EC_SECT163K1 => KeyLength::Ec(Sect163K1),
        YACA_KEY_LENGTH_EC_SECT163R1 => KeyLength::Ec(Sect163R1),
        YACA_KEY_LENGTH_EC_SECT163R2 => KeyLength::Ec(Sect163R2),
        YACA_KEY_LENGTH_EC_SECT193R1 => KeyLength::Ec(Sect193R1),
        YACA_KEY_LENGTH_EC_SECT193R2 => KeyLength::Ec(Sect193R2),
        YACA_KEY_LENGTH_EC_SECT233K1 => KeyLength::Ec(Sect233K1),
        YACA_KEY_LENGTH_EC_SECT233R1 => KeyLength::Ec(Sect233R1),
        YACA_KEY_LENGTH_EC_SECT239K1 => KeyLength::Ec(Sect239K1),
        YACA_KEY_LENGTH_EC_SECT283K1 => KeyLength::Ec(Sect283K1),
        YACA_KEY_LENGTH_EC_SECT283R1 => KeyLength::Ec(Sect283R1),
        YACA_KEY_LENGTH_EC_SECT409K1 => KeyLength::Ec(Sect409K1),
        YACA_KEY_LENGTH_EC_SECT409R1 => KeyLength::Ec(Sect409R1),
        YACA_KEY_LENGTH_EC_SECT571K1 => KeyLength::Ec(Sect571K1),
        YACA_KEY_LENGTH_EC_SECT571R1 => KeyLength::Ec(Sect571R1),

        YACA_KEY_LENGTH_EC_BRAINPOOLP160R1 => KeyLength::Ec(BrainpoolP160R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP160T1 => KeyLength::Ec(BrainpoolP160T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP192R1 => KeyLength::Ec(BrainpoolP192R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP192T1 => KeyLength::Ec(BrainpoolP192T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP224R1 => KeyLength::Ec(BrainpoolP224R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP224T1 => KeyLength::Ec(BrainpoolP224T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP256R1 => KeyLength::Ec(BrainpoolP256R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP256T1 => KeyLength::Ec(BrainpoolP256T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP320R1 => KeyLength::Ec(BrainpoolP320R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP320T1 => KeyLength::Ec(BrainpoolP320T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP384R1 => KeyLength::Ec(BrainpoolP384R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP384T1 => KeyLength::Ec(BrainpoolP384T1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP512R1 => KeyLength::Ec(BrainpoolP512R1),
        YACA_KEY_LENGTH_EC_BRAINPOOLP512T1 => KeyLength::Ec(BrainpoolP512T1),

        bl => {
            debug_assert!(bl % 8 == 0, "key_bit_length passed from C is not divisable by 8: {}", bl);
            debug_assert!(bl >= 8 && bl <= MAX_BITS, "Wrong key_bit_length passed from C: {}", bl);
            KeyLength::Bits(bl as u16)
        },
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
        EncryptAlgorithm::UnsafeTripleDes2Tdea => YACA_ENCRYPT_UNSAFE_3DES_2TDEA,
        EncryptAlgorithm::TripleDes3Tdea => YACA_ENCRYPT_3DES_3TDEA,
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
