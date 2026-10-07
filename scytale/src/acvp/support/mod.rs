//! Shared test support: vector loading and generic ACVP drivers.
//!
//! The drivers are generic over the primitive's trait, so every
//! implementation of a primitive is checked against the same
//! vectors.

#![allow(dead_code)]

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

pub mod acvp;
pub mod cfrg;
pub mod vectors;
pub mod wycheproof;
