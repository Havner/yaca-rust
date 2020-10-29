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
