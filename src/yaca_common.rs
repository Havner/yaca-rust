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

use libc::c_void;
use std::slice;

use crate::yaca_lib as lib;


pub(crate) fn vector_from_raw<U, T>(length: usize, data: *const U) -> Vec<T>
    where T: Clone,
{
    debug_assert!(!data.is_null());
    debug_assert!(length > 0);
    unsafe {
        let v = slice::from_raw_parts(data as *const T, length).to_vec();
        lib::yaca_free(data as *mut c_void);
        v
    }
}
