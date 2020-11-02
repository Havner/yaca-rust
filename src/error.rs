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

use std::error;
use std::fmt;


/// Enumeration of YACA error values returned from the C library
///
/// - All of the API functions return [`Result`] with an `Error`
///   embedded.
/// - If `Result::Err` is returned it will contain one of those
///   values.
/// - They are passed directly from the C YACA implementation.
/// - Some of the occurrences where YACA would return an error are
///   mitigated by Rust's type safety.
/// - Some of the occurrences where YACA would return `DataMismatch`
///   are converted to return `bool` in `Result:Ok`.
///
/// [`Result`]: type.Result.html
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid function parameter
    InvalidParameter,
    /// Out of memory
    OutOfMemory,
    /// Internal error
    Internal,
    /// Data mismatch
    DataMismatch,
    /// Invalid password
    InvalidPassword,
    /// Unknown error, should not happen
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
