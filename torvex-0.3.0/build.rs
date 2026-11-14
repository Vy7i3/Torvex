//! Builds the C++ indicator engine.
//!
//! The native library is compiled for every build, including tests. It has no
//! external dependencies beyond the C++ standard library, so a normal
//! `build-essential` toolchain is enough.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=native/torvex_core.cpp");
    println!("cargo:rerun-if-changed=native/torvex_core.h");
    println!("cargo:rerun-if-changed=python/torvex_audit.py");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .file("native/torvex_core.cpp")
        .include("native")
        .warnings(true)
        .flag_if_supported("-fno-strict-aliasing");

    // Optimise the matcher even in debug builds: a scanner that is unusably
    // slow under `cargo run` is not useful for development.
    build.opt_level(if env::var("PROFILE").as_deref() == Ok("release") {
        3
    } else {
        2
    });

    build.compile("torvex_core");
}
