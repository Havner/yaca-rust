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

use yaca::*;

mod common;


#[test]
fn crypto()
{
    let vec1 = common::MSG.to_vec();
    assert_eq!(memcmp(common::MSG, &vec1, common::MSG.len()).unwrap(), true);

    let vec2: Vec<u8> = common::MSG.into_iter().map(|c| c.to_ascii_uppercase()).collect();
    assert_eq!(memcmp(common::MSG, &vec2, common::MSG.len()).unwrap(), false);

    let len = 100;
    let rand_bytes1 = random_bytes(len).unwrap();
    assert_eq!(rand_bytes1.len(), len);
    let rand_bytes2 = random_bytes(len).unwrap();
    assert_eq!(rand_bytes2.len(), len);

    assert_eq!(memcmp(&rand_bytes1, &rand_bytes2, len).unwrap(), false);
}
