/*
 *  Copyright (c) 2021 Samsung Electronics Co., Ltd All Rights Reserved
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

use std::ptr;

use crate::yaca_common as common;
use crate::yaca_lib as lib;

pub use lib::keymaster_tag_type_t as tag_type_t;
pub use lib::keymaster_tag_t as tag_t;
pub use lib::keymaster_key_format_t as key_format_t;
pub use lib::keymaster_blob_t as blob_t;
pub use lib::keymaster_key_param_content_t as key_param_content_t;
pub use lib::keymaster_key_param_t as key_param_t;
pub use lib::keymaster_error_t as error_t;

pub use lib::keymaster_tag_get_type as tag_get_type;
pub use lib::keymaster_tag_mask_type as tag_mask_type;
pub use lib::keymaster_tag_type_repeatable as tag_type_repeatable;
pub use lib::keymaster_tag_repeatable as tag_repeatable;
pub use lib::keymaster_param_enum as param_enum;
pub use lib::keymaster_param_int as param_int;
pub use lib::keymaster_param_long as param_long;
pub use lib::keymaster_param_blob as param_blob;
pub use lib::keymaster_param_date as param_date;
pub use lib::keymaster_param_bool as param_bool;
pub use lib::keymaster_free_param_values as free_param_values;


pub fn build_wrapped_key(transit_key: &[u8], iv: &[u8], key_format: key_format_t,
                         secure_key: &[u8], tag: &[u8], auth_data: &[key_param_t])->
    std::result::Result<Vec<u8>, error_t>
{
    let mut der = ptr::null();
    let mut der_size = 0;
    let err;
    unsafe {
        err = lib::build_wrapped_key(transit_key.as_ptr(), transit_key.len(),
                                     iv.as_ptr(), iv.len(),
                                     key_format,
                                     secure_key.as_ptr(), secure_key.len(),
                                     tag.as_ptr(), tag.len(),
                                     auth_data.as_ptr(), auth_data.len(),
                                     &mut der, &mut der_size);
    }

    if error_t::KmErrorOk != err {
        Err(err)
    } else {
        Ok(common::vector_from_raw(der_size, der))
    }
}

pub fn parse_wrapped_key(der: &[u8])->
    std::result::Result<(
        /*iv*/Vec<u8>, /*transit_key*/Vec<u8>, /*secure_key*/Vec<u8>,
        /*tag*/Vec<u8>, /*auth_data*/Vec<key_param_t>,
        /*key_format*/key_format_t,
        /*der_desc*/Vec<u8>), error_t>
{
    let mut iv = ptr::null();
    let mut iv_size = 0;
    let mut transit_key = ptr::null();
    let mut transit_key_size = 0;
    let mut secure_key = ptr::null();
    let mut secure_key_size = 0;
    let mut tag = ptr::null();
    let mut tag_size = 0;
    let mut auth_data = ptr::null();
    let mut auth_data_size = 0;
    let mut key_format = key_format_t::KmKeyFormatX509;
    let mut der_desc = ptr::null();
    let mut der_desc_size = 0;
    let err;

    unsafe {
        err = lib::parse_wrapped_key(der.as_ptr(), der.len(),
                                     &mut iv, &mut iv_size,
                                     &mut transit_key, &mut transit_key_size,
                                     &mut secure_key, &mut secure_key_size,
                                     &mut tag, &mut tag_size,
                                     &mut auth_data, &mut auth_data_size, &mut key_format,
                                     &mut der_desc, &mut der_desc_size);
    }
    if error_t::KmErrorOk != err {
        Err(err)
    } else {
        Ok((common::vector_from_raw(iv_size, iv),
            common::vector_from_raw(transit_key_size, transit_key),
            common::vector_from_raw(secure_key_size, secure_key),
            common::vector_from_raw(tag_size, tag),
            common::vector_from_raw(auth_data_size, auth_data), key_format,
            common::vector_from_raw(der_desc_size, der_desc)))
    }
}
