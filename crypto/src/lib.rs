// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT
#![feature(const_fn, const_if_match)]

use failure::Fail;

#[macro_use]
pub mod blake2b;
pub mod base58;
pub mod nonce;
pub mod crypto_box;
#[macro_use]
pub mod hash;

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "invalid nonce size: {}", _0)]
    InvalidNonceSize(usize),
    #[fail(display = "failed to decrypt")]
    FailedToDecrypt,
}