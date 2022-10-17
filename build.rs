extern crate cbindgen;

use std::env;
use cbindgen::{Language};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    cbindgen::Builder::new()
        .with_parse_expand(&["rabe-ffi"],)
        .with_crate(crate_dir)
        .with_parse_deps(false)
        .with_language(Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("rabe.h");
}