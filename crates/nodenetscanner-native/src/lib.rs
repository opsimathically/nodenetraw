//! Linux-native bounded scanner runtime and Node-API adapter.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![cfg_attr(test, allow(dead_code))]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("nodenetscanner-native supports Linux only");

mod binding;
mod error;
mod model;
mod runtime;
mod session;
mod socket;
mod wire;
